# MaxMind DB File Format Specification

Source: https://maxmind.github.io/MaxMind-DB/

## Description

The MaxMind DB format is a database system that maps IPv4 and IPv6 addresses to
data records using an efficient binary search tree architecture.

## Version

This specification documents **version 2.0** of the MaxMind DB binary format.
Version numbers comprise separate major and minor components and should not be
interpreted as decimal values (version 2.10 follows 2.9). Code reading a major
version should remain compatible with minor version updates.

## Overview

The binary database consists of three primary sections:

1. **Binary search tree** — Each tree level corresponds to one bit in the network prefix
2. **Data section** — Contains values for networks, ranging from simple strings to complex maps/arrays
3. **Database metadata** — Information describing the database itself

## Database Metadata

Located at the file's end, metadata begins after the sequence `\xab\xcd\xefMaxMind.com`.
The _last_ occurrence marks the data section's end. Maximum metadata size is 128KiB
including the marker.

Metadata is stored as a map structure. Required keys:

| Key | Type | Description |
|-----|------|-------------|
| `node_count` | uint32 | number of search tree nodes |
| `record_size` | uint16 | bits per record (multiple of 4, minimum 24) |
| `ip_version` | uint16 | 4 or 6 |
| `database_type` | string | describes data record structure |
| `binary_format_major_version` | uint16 | format major version |
| `binary_format_minor_version` | uint16 | format minor version |
| `build_epoch` | uint64 | Unix timestamp of database build |

Optional keys: `languages` (array of locale codes), `description` (map of lang→UTF-8 string).

### Search Tree Size

```
search_tree_size = ((record_size * 2) / 8) * node_count
```

## Binary Search Tree Section

The file begins with the binary search tree. Node 0 is at the section's start.
Each node contains two records (left/right pointers) that reference:

- Another tree node: `value < node_count`
- No data: `value == node_count`
- Data section address: `value > node_count`

### Node Layouts

**24-bit records** (6 bytes per node):
```
| 23 .. 0          |          23 .. 0 |
```

**28-bit records** (7 bytes per node):
```
| 23 .. 0 | 27..24 | 27..24 | 23 .. 0 |
```

**32-bit records** (8 bytes per node):
```
| 31 .. 0          |          31 .. 0 |
```

### Lookup Algorithm

1. Convert IP to big-endian binary (32 bits for IPv4, 128 for IPv6)
2. Each bit selects left (0) or right (1) record in the current node
3. `value < node_count` → traverse to that node
4. `value == node_count` → no data for this address
5. `value > node_count` → pointer into data section

Data section offset:

```
data_section_offset = (record_value - node_count) - 16
file_offset         = (record_value - node_count) + search_tree_size
```

### IPv4 in IPv6 Trees

IPv4 addresses occupy the lowest 32 bits of the 128-bit space. MaxMind aliases:

- `::ffff:0:0/96` (IPv4-mapped)
- `2002::/16` (6to4)

Teredo (`2001::/32`) requires special handling (XOR-encoded, no tree alias).

## Data Section Separator

16 zero bytes separate the search tree from the data section.
Data section starts at `search_tree_size + 16` bytes into the file.

## Output Data Section

Each field begins with a control byte encoding type and payload size.
All binary data is big-endian.

### Data Types

| Type ID | Name | Notes |
|---------|------|-------|
| 1 | pointer | reference to another data section location |
| 2 | UTF-8 string | variable-length |
| 3 | double | IEEE-754 binary64, 8 bytes |
| 4 | bytes | variable-length binary |
| 5 | uint16 | 0–2 bytes |
| 6 | uint32 | 0–4 bytes |
| 7 | map | key/value pairs; keys always UTF-8; size = pair count |
| 8 | int32 | 2's complement, 0–4 bytes |
| 9 | uint64 | 0–8 bytes |
| 10 | uint128 | 0–16 bytes |
| 11 | array | ordered values; size = element count |
| 14 | boolean | true/false |
| 15 | float | IEEE-754 binary32, 4 bytes |

Type 0 in the control byte means extended type — the actual type is in the
following byte (offset by 7: stored value 1 = type 8, etc.).

### Control Byte

- Bits 7–5: type (0 = extended)
- Bits 4–0: payload size indicator
  - 0–28: direct byte count
  - 29: size = 29 + next byte (max 284)
  - 30: size = 285 + next two bytes (max 65,820)
  - 31: size = 65,821 + next three bytes (max 16,843,036)

### Pointer Encoding

Pointer size field uses `SS VVV` format in the low 5 bits:

| SS | Value | Offset |
|----|-------|--------|
| 0 | 11-bit | 0 |
| 1 | 19-bit | +2,048 |
| 2 | 27-bit | +526,336 |
| 3 | 32-bit (4 additional bytes) | 0 |

## License

Creative Commons Attribution-ShareAlike 3.0 Unported License
