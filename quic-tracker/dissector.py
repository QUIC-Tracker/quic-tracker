import struct
from base64 import b64decode

import itertools
import yaml
from hexdump import hexdump

packet = "/X2Vvy5oHiFm/wAACWBxbDoWAETEQvLzVywFokej+d/ZLabcAXliHotfW5fawFuIex6nPdH7I5AuQ6BkRrNKM1v7fHBQYlgYAc7d63nSmwsJA2NvCDTg2kNzuGBmQM2BOO0/k87LkYhT/GnX3f65ZEcJ08THZfAVluwhZFO4fsdBb6Lf5RBdD6tGiVeVjYKF2jcdBfHQZj/CJim7IzrSnApjcMfT8Ea8nNkm028dRQlBgui9cxfjREPctWHop1kXLanmAz9uSvqxmFc+ks/pdFUc13EAcvMeumCJetv5dXbYOWww6X1lek1qtCWZslf7ooYnjtMhz+vdEI5+9Kvfpcs7WAOIWqVIhymMNFb+KTCdJC9s3Hjt0fKDok9dYGBfm8UbFTqhwfsu0xK+GtWLpgBuW4G99Qo0jh6MrC2XYH7TytoK2rCuHZkI3BQhVFzYfCL+32Fi5u2fBdj7PvrHkZmtWVyzKua2fO6x+dibnFle7sjV1dix4VwJqQ1sYfEGejaHrzVTHGJH7neCfn+XiNez2HR44FkAFviD1SwgIiuxOa//nwikp9lXqn/soKlkuxcDAwEZC7qHRCJjIrogivWzpHFu345bOEVghVOJhHt6vz0abZ5B65PoV/25KNZbb/8r/CaDrcZScoyNjZsvUsT2Nkc7C3oL5ow42Ozn8jWw+v0R3W0peH7BNDlLyYv2gJQyiudkWvW+AYDlH6sd/g475/U2jh89+huo76bEvDMQuvDHAdF/ucTP9EHbsAu6eJ5R2dQdX2aUDay2O73GjYS85Cm2YVsbmYMKGr2CCUNhPmBHRSSDzOsQEUFVXSq0+Ui+w3JYVQN++MnKNSoTPd9Lv25gAcTX7WD2cfxT7aTMuXeLz1ATB0lXFgRZl6FDyhzdOsYLoNZDNx8EGMlY9F5277mZvyyeVKGHD1iEa1nEfHiqmognsY8hEPqH940XAwMANWJ2tiG4p5Ggh7cNBa8nICwddAdXW0tPulQ/yy05411QAgvRVNaVpawgCDorGUzFhcO5Pkim"
packet2 = "/+lSIJDr2kW8/wAACWvaRb0SAEJ/FgMDAnoBAAJ2AwM2WWZT0TlZympEhBwMKUvSMOu+k7dbpYkmwuB7PNzwVAAABBMBEwIBAAJJACsAAwJ/FwAAABIAEAAADXF1aWMub2dyZS5jb20AMwHUAdIAFwBBBKJdJhadPFopOwygNL3TUAbQy7OxAwLOa3Srzm12XUxSohisf/HPrqM1YCdgZ41TN//FpKXB4v/4SW5zBCbDqJAAGABhBMNZI2n3Q4IkXXLQTtMG1y5KBavoYp3vrd3k6TsxT1YlOptiqlQitAK5tFnst71tQ/dIsSgMKMgcraDEYV6i5xyIkpPW4AbvyFc14x5kXvJ4YWgraIneHmJKPb1+5wAvMAEAAQAgjXLK9j7mKuxEFORsvqGSIQy3W3CTf4tKKVEZymshkmnDSrF/Uvr5ynK9/YoMfLt08LRyrOZSOzKVVAEjuo3h1StLZFeHrsaAZ2+VMkOizmnlhk302T0cqkkoEgjrW6LUZFmMC+dSrIZ40QKXeY1tyDN/WmX9S+e6mo+GznOQOfT1n+MQ3L+44KhBZQV6ZOX6IEPKYlQufxz/Wwo4rbTpXlhIdy46AKxPK6I9JpQZYplTyN8ZdyvncpXwVLw8X2eakIFsgMYRp5DLqPxWo4MOCRr0N5GsG+d5A9+6bYvIWn1C4IjV1r1og9NqE57cgm6RKFkzmI8pp2uq0JpiHjZxAB0AIAfA+XsA9itcnLiGWjf+SUJclvoIELzKJIgT54Vw/T8CAAoACgAIABcAGAEAAB0ADQAOAAwIBAgFCAYEAwUDBgMAEAAIAAYFaHEtMDkAGgAk/wAACQAeAAAABAAAAFAAAQAEAACAAAACAAQAAAARAAMAAgAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
packet3 = "/X2Vvy5oHiFm/wAACWvaRb4OwAAAAGBxbDgAAAA="
packet4 = "/X2Vvy5oHiFm/wAACWvaRcAWAEJ/OhcDAwA19YpFSRK4K4S2F/jZOx8wh44ZV09z9uUCmvk+hONCu+INYWSjwwCRdyepuI/r3bhrD2yNAJ4OwAAAAGBxbDoAAAI="
packet5 = "HX2Vvy5oHiFma9pFwRIEB0dFVCAvDQoOwAAAAGBxbDoAAAI="

class ParseError(ValueError):
    pass


def parse_packet(buffer, protocol):
    top_level = protocol.pop('top')
    for top_struct in top_level:
        next_struct = top_struct
        while next_struct and len(buffer) > 1:
            try:
                ret, inc, next_struct = parse_structure(buffer, protocol[next_struct], protocol)
                print(ret, inc, next_struct)
                buffer = buffer[inc:]
                return
            except ParseError as e:
                #print('%s: %s' % (top_struct, e))
                break


def yield_structures(buffer, struct_name, protocol):
    next_struct = struct_name
    while next_struct and buffer:
        if next_struct not in protocol:
            ret, inc, next_struct = parse_structure_type(buffer, next_struct, protocol)
        else:
            ret, inc, next_struct = parse_structure(buffer, protocol[next_struct], protocol)
        yield ret, inc
        buffer = buffer[inc:]


def parse_structure_type(buffer, type_name, protocol):
    def get_struct_type(structure_description):
        for field, args in (list(d.items())[0] for d in structure_description):
            if field == 'type':
                return args

    structures = [(k, v) for k, v in protocol.items() if get_struct_type(v) == type_name]

    for struct_name, struct_description in structures:
        try:
            struct, inc, next_struct = parse_structure(buffer, struct_description, protocol)
            return (struct_name, struct), inc, next_struct
        except ParseError as e:
            #print('%s: %s' % (struct_name, e))
            continue

    return (None, []), 0, None


def parse_structure(buffer, structure_description, protocol):
    structure = []
    struct_triggers = {}
    i = 0
    previous_len = 0
    next_struct = None

    for field, args in (list(d.items())[0] for d in structure_description):
        if field == 'next':
            next_struct = args
            break
        elif field == 'type':
            continue

        length = struct_triggers.get(field, {}).get('length', args.get('length'))
        values = struct_triggers.get(field, {}).get('values', args.get('values'))
        parse = struct_triggers.get(field, {}).get('parse', args.get('parse'))
        conditions = struct_triggers.get(field, {}).get('conditions', args.get('conditions'))
        triggers = struct_triggers.get(field, {}).get('triggers', args.get('triggers'))

        if conditions:
            if not all(verify_condition(structure, field, formula) for c in conditions for field, formula in c.items()):
                continue

        if parse:
            for _ in range(length if length is not None else 1):
                for ret, inc in yield_structures(buffer, parse, protocol):
                    structure.append((field, ret))
                    i += inc
            continue
        elif length:
            if length == 'varint':
                val, length = read_varint(buffer)
            elif length == '*':
                val = buffer
                length = len(buffer) * 8
            elif length >= 8:
                val = read(buffer, length//8)
            else:
                mask = (0xff << (8 - length)) & 0xff
                val = (buffer[0] & mask) >> (8 - length)
                if previous_len < 8 <= previous_len + length and (previous_len + length) % 8 == 0:
                    length = previous_len + length
                else:
                    buffer = buffer[:]
                    buffer[0] = (buffer[0] << length) & 0xff
                    if previous_len < 8:
                        length = previous_len + length
            structure.append((field, val))
            if length >= 8:
                buffer = buffer[length//8:]
                i += length//8

        if values is not None:
            if type(values) is dict:
                err = ParseError('Value %s for field %s does not fullfill conditions %s' % (str(val), str(field), str(values)))
                for op, v in values.items():
                    if op == 'eq' and val != v:
                        raise err
                    elif op == 'neq' and val == v:
                        raise err
            elif (type(values) is list and val not in values) or (type(values) is not list and val != values):
                raise ParseError('Value %s for field %s not acceptable (%s)' % (str(val), str(field), str(values)))

        if triggers:
            for trigger_field, actions in itertools.chain.from_iterable(t.items() for t in triggers):
                for attribute, action in actions.items():
                    d = struct_triggers.get(trigger_field, {})
                    if action == 'set':
                        d[attribute] = val * 8 if attribute == 'length' else val
                    elif type(action) is dict:
                        d[attribute] = action[val]
                    struct_triggers[trigger_field] = d

        previous_len = length

    return structure, i, next_struct


def read(buffer, length):
    _len_to_format_char = {
        1: 'B',
        2: 'H',
        4: 'I',
        8: 'Q',
        16: '16B',
    }
    if length not in _len_to_format_char:
        return buffer[:length]
    return struct.unpack('!'+_len_to_format_char.get(length), buffer[:length])[0]


def read_varint(buffer):
    length = 2 ** ((buffer[0] & 0xc0) >> 6)
    buffer[0] &= 0x3f
    return read(buffer, length), length * 8


def verify_condition(structure, field, formula):
    for f, v in structure:
        if f == field:
            if 'eq' in formula:
                return v == formula['eq']
            elif 'neq' in formula:
                return v != formula['neq']
    return False


if __name__ == "__main__":
    with open('protocol.yaml') as f:
        protocol = yaml.load(f)
    hexdump(b64decode(packet5))
    for _ in range(100000):
        pass
    parse_packet(bytearray(b64decode(packet5)), protocol)
