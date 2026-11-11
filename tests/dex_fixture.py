"""Tiny synthetic DEX for static parser regression tests, never installed or executed.

Four functions: clean, source only, sink only, and both APIs in one method.
No code sends data; references exist solely to exercise real DEX cross references.
"""
import hashlib
import struct
import zlib


def uleb(value):
    data = bytearray()
    while value >= 128:
        data.append((value & 127) | 128)
        value >>= 7
    data.append(value)
    return bytes(data)


def make_dex():
    app = 'Lorg/example/Main;'
    source, sink = 'Landroid/location/Location;', 'Ljava/net/HttpURLConnection;'
    types = [app, source, sink, 'Ljava/lang/Object;', 'Ljava/io/OutputStream;', 'V', 'D']
    names = ['clean', 'sourceOnly', 'sinkOnly', 'leak', 'getLatitude', 'getOutputStream']
    strings = sorted(set(types + names + ['L']))
    string_idx = {s: i for i, s in enumerate(strings)}
    types.sort(key=string_idx.get)
    type_idx = {s: i for i, s in enumerate(types)}
    protos = sorted(['V', 'D', 'Ljava/io/OutputStream;'], key=type_idx.get)
    proto_idx = {s: i for i, s in enumerate(protos)}
    methods = [(app, n, 'V') for n in names[:4]] + [(source, 'getLatitude', 'D'), (sink, 'getOutputStream', 'Ljava/io/OutputStream;')]
    methods.sort(key=lambda m: (type_idx[m[0]], string_idx[m[1]], proto_idx[m[2]]))
    method_idx = {m[1]: i for i, m in enumerate(methods)}
    string_off = 112
    type_off = string_off + 4 * len(strings)
    proto_off = type_off + 4 * len(types)
    method_off = proto_off + 12 * len(protos)
    class_off = method_off + 8 * len(methods)
    data_off = class_off + 32
    out = bytearray(data_off)
    string_data_offsets = []
    for string in strings:
        string_data_offsets.append(len(out))
        out.extend(uleb(len(string)) + string.encode() + b'\0')

    def align():
        while len(out) % 4:
            out.append(0)

    code_offsets = {}
    code_start = None
    for name in sorted(names[:4], key=method_idx.get):
        align()
        code_start = code_start or len(out)
        code_offsets[name] = len(out)
        instructions = []
        for target in (['getLatitude'] if name == 'sourceOnly' else ['getOutputStream'] if name == 'sinkOnly' else ['getLatitude', 'getOutputStream'] if name == 'leak' else []):
            instructions.extend([0x106e, method_idx[target], 0])  # invoke-virtual {v0}
        instructions.append(0x000e)  # return-void
        out.extend(struct.pack('<HHHHII', 1, 0, 1, 0, 0, len(instructions)))
        out.extend(struct.pack('<' + 'H' * len(instructions), *instructions))
    class_data_off = len(out)
    out.extend(b'\0\0' + uleb(4) + b'\0')
    previous = 0
    for name in sorted(names[:4], key=method_idx.get):
        idx = method_idx[name]
        out.extend(uleb(idx - previous) + uleb(9) + uleb(code_offsets[name]))
        previous = idx
    align()
    map_off = len(out)
    entries = [(0, 1, 0), (1, len(strings), string_off), (2, len(types), type_off),
               (3, len(protos), proto_off), (5, len(methods), method_off), (6, 1, class_off),
               (0x2002, len(strings), data_off), (0x2001, 4, code_start),
               (0x2000, 1, class_data_off), (0x1000, 1, map_off)]
    entries.sort(key=lambda x: x[2])
    out.extend(struct.pack('<I', len(entries)))
    for kind, size, offset in entries:
        out.extend(struct.pack('<HHII', kind, 0, size, offset))
    for i, offset in enumerate(string_data_offsets):
        struct.pack_into('<I', out, string_off + 4 * i, offset)
    for i, typ in enumerate(types):
        struct.pack_into('<I', out, type_off + 4 * i, string_idx[typ])
    for i, typ in enumerate(protos):
        shorty = typ if len(typ) == 1 else 'L'
        struct.pack_into('<III', out, proto_off + 12 * i, string_idx[shorty], type_idx[typ], 0)
    for i, (owner, name, ret) in enumerate(methods):
        struct.pack_into('<HHI', out, method_off + 8 * i, type_idx[owner], proto_idx[ret], string_idx[name])
    struct.pack_into('<8I', out, class_off, type_idx[app], 1, type_idx['Ljava/lang/Object;'],
                     0, 0xffffffff, 0, class_data_off, 0)
    struct.pack_into('<8sI20s20I', out, 0, b'dex\n035\0', 0, bytes(20),
                     len(out), 112, 0x12345678, 0, 0, map_off,
                     len(strings), string_off, len(types), type_off, len(protos), proto_off,
                     0, 0, len(methods), method_off, 1, class_off, len(out) - data_off, data_off)
    out[12:32] = hashlib.sha1(out[32:]).digest()
    struct.pack_into('<I', out, 8, zlib.adler32(out[12:]) & 0xffffffff)
    return bytes(out)
