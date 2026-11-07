// SPDX-License-Identifier: MIT
// Read-only PCI inventory from public IOKit properties. No device filtering.
// Legacy procfs field layout: Linux drivers/pci/proc.c, show_device().
#pragma once
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <tuple>
#include <vector>

// Project existing physical platform text into the corresponding sysfs attribute.
// This does not construct SMBIOS tables or substitute a missing board identifier.
static int darwin_platform_identity(const std::string &path, std::string &text) {
  CFStringRef key = path == "/sys/devices/virtual/dmi/id/product_name" ? CFSTR("model")
                    : path == "/sys/devices/virtual/dmi/id/board_name" ? CFSTR("board-id")
                                                                       : nullptr;
  if (!key)
    return -2;
  io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
  if (!service)
    return -2;
  CFTypeRef raw = IORegistryEntryCreateCFProperty(service, key, kCFAllocatorDefault, 0);
  IOObjectRelease(service);
  std::unique_ptr<const void, decltype(&CFRelease)> value(raw, CFRelease);
  if (!raw)
    return -2;
  if (CFGetTypeID(raw) == CFStringGetTypeID()) {
    char buffer[4096];
    if (!CFStringGetCString(static_cast<CFStringRef>(raw), buffer, sizeof(buffer), kCFStringEncodingUTF8))
      return -95;
    text = buffer;
  } else if (CFGetTypeID(raw) == CFDataGetTypeID()) {
    auto data = static_cast<CFDataRef>(raw);
    CFIndex size = CFDataGetLength(data);
    if (size < 1 || size > 4096)
      return -95;
    const char *bytes = reinterpret_cast<const char *>(CFDataGetBytePtr(data));
    while (size && !bytes[size - 1])
      --size;
    if (memchr(bytes, 0, size))
      return -95;
    text.assign(bytes, size);
  } else
    return -95;
  if (text.empty() || text.find_first_of("\r\n") != std::string::npos)
    return -95;
  text += '\n';
  return 0;
}

static int darwin_pci_inventory(std::string &text) {
  struct Row {
    uint32_t bus, devfn, vendor, device, irq = 0;
    std::array<uint64_t, 7> starts{}, lengths{};
  };
  std::vector<Row> rows;
  io_iterator_t iterator = IO_OBJECT_NULL;
  if (IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching("IOPCIDevice"), &iterator))
    return -5;
  int error = 0;
  while (io_service_t service = IOIteratorNext(iterator)) {
    CFMutableDictionaryRef raw = nullptr;
    kern_return_t status = IORegistryEntryCreateCFProperties(service, &raw, kCFAllocatorDefault, 0);
    IOObjectRelease(service);
    std::unique_ptr<const void, decltype(&CFRelease)> properties(raw, CFRelease);
    if (status || !raw) {
      error = -5;
      break;
    }
    auto data = [raw](CFStringRef key) -> CFDataRef {
      CFTypeRef value = CFDictionaryGetValue(raw, key);
      return value && CFGetTypeID(value) == CFDataGetTypeID() ? static_cast<CFDataRef>(value) : nullptr;
    };
    auto word = [](CFDataRef bytes, CFIndex offset, uint32_t &value) {
      if (!bytes || offset < 0 || CFDataGetLength(bytes) < offset + 4)
        return false;
      const UInt8 *p = CFDataGetBytePtr(bytes) + offset;
      value = uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
      return true;
    };
    auto number = [](CFDictionaryRef dictionary, CFStringRef key, uint64_t &value) {
      CFTypeRef property = CFDictionaryGetValue(dictionary, key);
      int64_t result = -1;
      if (!property || CFGetTypeID(property) != CFNumberGetTypeID() ||
          !CFNumberGetValue(static_cast<CFNumberRef>(property), kCFNumberSInt64Type, &result) || result < 0)
        return false;
      value = uint64_t(result);
      return true;
    };
    Row row{};
    uint32_t address;
    CFDataRef reg = data(CFSTR("reg"));
    if (!word(data(CFSTR("vendor-id")), 0, row.vendor) || row.vendor > 0xffff ||
        !word(data(CFSTR("device-id")), 0, row.device) || row.device > 0xffff || !word(reg, 0, address)) {
      error = -95;
      break;
    }
    row.bus = (address >> 16) & 0xff;
    row.devfn = (address >> 8) & 0xff;
    CFTypeRef interrupts = CFDictionaryGetValue(raw, CFSTR("IOInterruptSpecifiers"));
    if (interrupts) {
      CFTypeRef controllers = CFDictionaryGetValue(raw, CFSTR("IOInterruptControllers"));
      if (CFGetTypeID(interrupts) != CFArrayGetTypeID() || !controllers ||
          CFGetTypeID(controllers) != CFArrayGetTypeID()) {
        error = -95;
        break;
      }
      auto specs = static_cast<CFArrayRef>(interrupts), names = static_cast<CFArrayRef>(controllers);
      CFIndex count = CFArrayGetCount(specs), chosen = 0;
      if (count != CFArrayGetCount(names) || count > 256) {
        error = -95;
        break;
      }
      CFTypeRef mode = CFDictionaryGetValue(raw, CFSTR("IOPCIMSIMode"));
      if (mode == kCFBooleanTrue && count) {
        chosen = -1;
        for (CFIndex i = 0; i < count; ++i) {
          CFTypeRef controller = CFArrayGetValueAtIndex(names, i);
          if (CFGetTypeID(controller) == CFStringGetTypeID() &&
              CFStringFind(static_cast<CFStringRef>(controller), CFSTR("MSI"), 0).location != kCFNotFound) {
            chosen = i;
            break;
          }
        }
        if (chosen < 0) {
          error = -95;
          break;
        }
      }
      if (count) {
        CFTypeRef spec = CFArrayGetValueAtIndex(specs, chosen);
        if (CFGetTypeID(spec) != CFDataGetTypeID() || !word(static_cast<CFDataRef>(spec), 0, row.irq)) {
          error = -95;
          break;
        }
      }
    }
    CFDataRef assigned = data(CFSTR("assigned-addresses"));
    if (assigned) {
      CFTypeRef memory = CFDictionaryGetValue(raw, CFSTR("IODeviceMemory"));
      CFIndex length = CFDataGetLength(assigned), count = length / 20;
      if (length % 20 || count > 7 || !memory || CFGetTypeID(memory) != CFArrayGetTypeID() ||
          CFArrayGetCount(static_cast<CFArrayRef>(memory)) != count) {
        error = -95;
        break;
      }
      for (CFIndex i = 0; i < count; ++i) {
        uint32_t space, size_low, size_high;
        if (!word(assigned, i * 20, space) || !word(assigned, i * 20 + 12, size_low) ||
            !word(assigned, i * 20 + 16, size_high) || ((space ^ address) & 0x00ffff00)) {
          error = -95;
          break;
        }
        unsigned config = space & 0xff;
        int slot = config == 0x30 ? 6 : config >= 0x10 && config <= 0x24 && !(config & 3) ? (config - 0x10) / 4 : -1;
        unsigned kind = (space >> 24) & 3;
        CFTypeRef segments = CFArrayGetValueAtIndex(static_cast<CFArrayRef>(memory), i);
        if (slot < 0 || !kind || CFGetTypeID(segments) != CFArrayGetTypeID() ||
            CFArrayGetCount(static_cast<CFArrayRef>(segments)) != 1) {
          error = -95;
          break;
        }
        CFTypeRef segment = CFArrayGetValueAtIndex(static_cast<CFArrayRef>(segments), 0);
        uint64_t start, size;
        if (CFGetTypeID(segment) != CFDictionaryGetTypeID() ||
            !number(static_cast<CFDictionaryRef>(segment), CFSTR("address"), start) ||
            !number(static_cast<CFDictionaryRef>(segment), CFSTR("length"), size) ||
            size != (uint64_t(size_high) << 32 | size_low) || row.lengths[slot] || size > UINT64_MAX - start) {
          error = -95;
          break;
        }
        uint64_t flags = kind == 1 ? 1 : kind == 3 ? 4 : 0;
        if (kind != 1 && (space & 0x40000000))
          flags |= 8;
        if (start & 15) {
          error = -95;
          break;
        }
        row.starts[slot] = start | flags;
        row.lengths[slot] = size > 1 ? size : 0;
      }
      if (error)
        break;
    } else if (CFDictionaryContainsKey(raw, CFSTR("assigned-addresses")) || CFDataGetLength(reg) > 20) {
      error = -95;
      break; // Do not omit resources whose native representation is unavailable.
    }
    rows.push_back(row);
    if (rows.size() > 65536) {
      error = -75;
      break;
    }
  }
  if (!IOIteratorIsValid(iterator) && !error)
    error = -11;
  IOObjectRelease(iterator);
  if (error)
    return error;
  std::stable_sort(rows.begin(), rows.end(), [](const Row &a, const Row &b) {
    return std::tie(a.bus, a.devfn, a.vendor, a.device) < std::tie(b.bus, b.devfn, b.vendor, b.device);
  });
  text.clear();
  for (const Row &row : rows) {
    char field[80];
    snprintf(field, sizeof(field), "%02x%02x\t%04x%04x\t%x", row.bus, row.devfn, row.vendor, row.device, row.irq);
    text += field;
    for (uint64_t value : row.starts) {
      snprintf(field, sizeof(field), "\t%16llx", static_cast<unsigned long long>(value));
      text += field;
    }
    for (uint64_t value : row.lengths) {
      snprintf(field, sizeof(field), "\t%16llx", static_cast<unsigned long long>(value));
      text += field;
    }
    text += "\t\n"; // No Linux driver is bound by this read-only inventory adapter.
  }
  return 0;
}
