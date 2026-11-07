// Normalize actual native mappings; ELF records provide origin metadata only.
struct NativeMapsRow {
  uint64_t start, end, offset, major, minor, inode;
  std::string permissions, name;
};
struct NativeElfOrigin {
  uint64_t start, end, offset;
  std::string name;
};
static bool normalize_native_maps(std::vector<NativeMapsRow> native, const std::vector<NativeElfOrigin> &origins,
                                  std::vector<NativeMapsRow> &output) {
  std::sort(native.begin(), native.end(), [](const auto &a, const auto &b) { return a.start < b.start; });
  uint64_t previous_end = 0;
  for (const auto &row : native) {
    if (row.end <= row.start || row.start < previous_end || row.permissions.size() != 4)
      return false;
    previous_end = row.end;
  }
  for (const auto &origin : origins) {
    if (origin.end <= origin.start)
      return false;
    uint64_t cursor = origin.start;
    for (const auto &row : native) {
      if (row.end <= cursor)
        continue;
      if (row.start > cursor)
        break;
      cursor = std::min(origin.end, row.end);
      if (cursor == origin.end)
        break;
    }
    if (cursor != origin.end)
      return false; // Do not report an unbacked ELF mapping.
  }
  output.clear();
  for (const auto &row : native) {
    std::vector<uint64_t> cuts{row.start, row.end};
    for (const auto &origin : origins)
      if (origin.start < row.end && row.start < origin.end) {
        cuts.push_back(std::max(row.start, origin.start));
        cuts.push_back(std::min(row.end, origin.end));
      }
    std::sort(cuts.begin(), cuts.end());
    cuts.erase(std::unique(cuts.begin(), cuts.end()), cuts.end());
    for (size_t i = 1; i < cuts.size(); ++i) {
      auto part = row;
      part.start = cuts[i - 1];
      part.end = cuts[i];
      part.offset += part.start - row.start;
      if (part.name.empty())
        for (const auto &origin : origins)
          if (origin.start <= part.start && part.end <= origin.end) {
            part.name = origin.name;
            part.offset = origin.offset + part.start - origin.start;
            break;
          }
      // Native permissions, existing names, device and inode fields are retained.
      output.push_back(std::move(part));
    }
  }
  return true;
}

// Report actual logical aliases installed in FEX, retaining their native backing rows.
static bool translate_native_alias_maps(const std::vector<NativeMapsRow> &native,
                                        const std::vector<RootAliasMetadata> &aliases,
                                        std::vector<NativeMapsRow> &output) {
  std::vector<NativeMapsRow> logical;
  for (const auto &alias : aliases) {
    if (!alias.length || alias.guest > UINT64_MAX - alias.length || alias.host > UINT64_MAX - alias.length ||
        alias.length > alias.span || alias.guest % 4096 || alias.length % 4096 || (alias.protection & ~uint64_t(7)))
      return false;
    for (const auto &other : logical)
      if (alias.guest < other.end && other.start < alias.guest + alias.length)
        return false;
    uint64_t cursor = alias.host;
    for (const auto &row : native) {
      if (row.end <= cursor)
        continue;
      if (row.start > cursor)
        break;
      const uint64_t end = std::min(row.end, alias.host + alias.length);
      // Executable x86 pages are read by the emulator, not executed as ARM instructions.
      // XNU shared reports current inter-process sharing, not the original MAP_SHARED request.
      // The alias comes from the successful real MAP_SHARED operation/FEX registration.
      const bool readable = (alias.protection & (PROT_READ | PROT_EXEC)) != 0;
      if ((readable && row.permissions[0] != 'r') || ((alias.protection & PROT_WRITE) && row.permissions[1] != 'w'))
        return false;
      NativeMapsRow part = row;
      part.start = alias.guest + cursor - alias.host;
      part.end = alias.guest + end - alias.host;
      part.offset = alias.offset + cursor - alias.host;
      part.permissions = {char(alias.protection & PROT_READ ? 'r' : '-'),
                          char(alias.protection & PROT_WRITE ? 'w' : '-'),
                          char(alias.protection & PROT_EXEC ? 'x' : '-'), 's'};
      logical.push_back(std::move(part));
      cursor = end;
      if (cursor == alias.host + alias.length)
        break;
    }
    if (cursor != alias.host + alias.length)
      return false;
  }
  output.clear();
  for (const auto &row : native) {
    std::vector<uint64_t> cuts{row.start, row.end};
    for (const auto &alias : logical)
      if (alias.start < row.end && row.start < alias.end) {
        cuts.push_back(std::max(row.start, alias.start));
        cuts.push_back(std::min(row.end, alias.end));
      }
    std::sort(cuts.begin(), cuts.end());
    cuts.erase(std::unique(cuts.begin(), cuts.end()), cuts.end());
    for (size_t i = 1; i < cuts.size(); ++i) {
      if (std::any_of(logical.begin(), logical.end(),
                      [&](const auto &a) { return a.start <= cuts[i - 1] && cuts[i] <= a.end; }))
        continue;
      auto part = row;
      part.start = cuts[i - 1];
      part.end = cuts[i];
      part.offset += part.start - row.start;
      output.push_back(std::move(part));
    }
  }
  output.insert(output.end(), logical.begin(), logical.end());
  std::sort(output.begin(), output.end(), [](const auto &a, const auto &b) { return a.start < b.start; });
  for (size_t i = 1; i < output.size(); ++i)
    if (output[i].start < output[i - 1].end)
      return false;
  return true;
}
