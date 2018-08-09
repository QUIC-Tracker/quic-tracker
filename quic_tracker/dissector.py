#
#   Maxime Piraux's master's thesis
#   Copyright (C) 2017-2018  Maxime Piraux
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU Affero General Public License version 3
#   as published by the Free Software Foundation.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU Affero General Public License for more details.
#
#   You should have received a copy of the GNU Affero General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
import builtins
import os
import struct
import itertools
import yaml

from quic_tracker.utils import join_root


class ParseError(ValueError):
    pass


def parse_packet(buffer, context):
    last_e = None
    for p in sorted(os.listdir(join_root('protocol')), reverse=True):
        with open(join_root('protocol', p)) as f:
            try:
                return p, parse_packet_with(buffer[:], protocol=yaml.load(f), context=context)
            except Exception as e:
                last_e = e
                continue
    raise last_e


def parse_packet_with(buffer, protocol, context):
    top_level = protocol.pop('top')
    last_e = None
    for top_struct in top_level:
        try:
            ret, inc, _ = parse_structure(buffer[:], protocol[top_struct], protocol, 0, context)
            if inc < len(buffer):
                raise ParseError('There are bytes left unparsed in the buffer')
            return [(top_struct, ('', ret, 0, inc), 0, inc)]
        except ParseError as e:
            last_e = e
            pass
    if last_e:
        raise last_e
    return []


def yield_structures(buffer, struct_name, protocol, start_idx, context):
    next_struct = struct_name
    while next_struct and buffer:
        if next_struct not in protocol:
            ret, inc, next_struct = parse_structure_type(buffer, next_struct, protocol, start_idx, context)
            yield ret, inc
        else:
            ret, inc, next_struct = parse_structure(buffer, protocol[next_struct], protocol, start_idx, context)
            yield (struct_name, ret), inc
        buffer = buffer[inc:]
        start_idx += inc


def parse_structure_type(buffer, type_name, protocol, start_idx, context):
    def get_struct_type(structure_description):
        for field, args in (list(d.items())[0] for d in structure_description):
            if field == 'type':
                return args

    structures = [(k, v) for k, v in protocol.items() if get_struct_type(v) == type_name]

    for struct_name, struct_description in structures:
        try:
            struct, inc, next_struct = parse_structure(buffer, struct_description, protocol, start_idx, context)
            return (struct_name, struct, start_idx, start_idx + inc), inc, next_struct
        except ParseError as e:
            #print('%s: %s' % (struct_name, e))
            continue
    raise ParseError('No structure could be parsed for type {}, first byte was {}'.format(type_name, buffer[0]))


def parse_structure(buffer, structure_description, protocol, start_idx, context):
    structure = []
    struct_triggers = {}
    i = 0
    previous_len = 0
    next_struct = None
    repeating = False
    successful_repeated = False

    structure_description = list(reversed(structure_description))
    while structure_description and buffer:
        field, args = list(structure_description.pop().items())[0]
        field_ctx = context.get(field, {})

        if field == 'next':
            next_struct = args
            continue
        elif field == 'type':
            continue

        length = struct_triggers.get(field, {}).get('length', field_ctx.get('length'))
        if length is not None and 'parse' in args:
            length //= 8
        if length is None:
            length = args.get('length')
        byte_length = struct_triggers.get(field, {}).get('byte_length', args.get('byte_length', field_ctx.get('byte_length')))
        format = struct_triggers.get(field, {}).get('format', args.get('format', field_ctx.get('format')))
        if format in vars(builtins):
            if format == 'hex':
                format = lambda x: hex(x) if type(x) is int else '0x' + x.hex()
            else:
                format = vars(builtins)[format]
        else:
            format = lambda x: x
        values = struct_triggers.get(field, {}).get('values', args.get('values', field_ctx.get('values')))
        parse = struct_triggers.get(field, {}).get('parse', args.get('parse', field_ctx.get('parse')))
        conditions = struct_triggers.get(field, {}).get('conditions', args.get('conditions', field_ctx.get('conditions')))
        triggers = struct_triggers.get(field, {}).get('triggers', args.get('triggers', field_ctx.get('triggers')))

        if 'repeated' in args and len(buffer) >= length//4:
            repeating = True

        if conditions:
            if not all(verify_condition(structure, field, formula) for c in conditions for field, formula in c.items()):
                continue

        if parse:
            parse_buf = buffer
            if byte_length:
                parse_buf = buffer[:start_idx + i + byte_length]
            for _ in range(length if length is not None else 1):
                for ret, inc in yield_structures(parse_buf, parse, protocol, start_idx + i, context):
                    structure.append((field, ret, start_idx + i, start_idx + i + inc))
                    i += inc
                    buffer = buffer[inc:]
                    parse_buf = parse_buf[inc:]
            continue
        elif length:
            if length == 'varint':
                val, length = read_varint(buffer)
            elif length == 'pn':
                val, length = read_pn(buffer)
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

            try:
                if values is not None:
                    if type(values) is dict:
                        err = ParseError('Value %s for field %s does not fulfill conditions %s' % (str(val), str(field), str(values)))
                        for op, v in values.items():
                            if op == 'eq' and val != v:
                                raise err
                            elif op == 'neq' and val == v:
                                raise err
                    elif (type(values) is list and val not in values) or (type(values) is not list and val != values):
                        raise ParseError('Value %s for field %s not acceptable (%s)' % (str(val), str(field), str(values)))
            except ParseError as e:
                if not (repeating and successful_repeated):
                    raise
                continue

            structure.append((field, format(val), start_idx + i, start_idx + i + (length//8 or 1)))

            if length >= 8:
                buffer = buffer[length//8:]
                i += length//8

        if triggers:
            for trigger_field, actions in itertools.chain.from_iterable(t.items() for t in triggers):
                if trigger_field == 'save_to_context':
                    context.update(struct_triggers)
                    continue

                for attribute, action in actions.items():
                    d = struct_triggers.get(trigger_field, {})
                    if action == 'set':
                        d[attribute] = val * 8 if attribute == 'length' else val
                        if val is 0:
                            structure_description = list(filter(lambda x: next(iter(x.items()))[0] != trigger_field, structure_description))
                    elif type(action) is dict:
                        d[attribute] = action[val]
                    struct_triggers[trigger_field] = d

        if repeating:
            successful_repeated = True
            structure_description.append({field: args})

        previous_len = length

    if not buffer and not repeating and structure_description:
        for field, args in list(structure_description.pop().items()):
            if field == 'next':
                continue
            field_ctx = context.get(field, {})
            length = struct_triggers.get(field, {}).get('length', field_ctx.get('length', args.get('length')))
            conditions = struct_triggers.get(field, {}).get('conditions', args.get('conditions', field_ctx.get('conditions')))
            if not length or not all(verify_condition(structure, field, formula) for c in conditions for field, formula in c.items()):
                continue
            raise ParseError('The structure has not been fully parsed')

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
        if length <= len(buffer):
            return buffer[:length]
        raise ParseError('{} bytes cannot be read from a {}-byte long buffer'.format(length, len(buffer)))
    return struct.unpack('!'+_len_to_format_char.get(length), buffer[:length])[0]


def read_varint(buffer):
    length = 2 ** ((buffer[0] & 0xc0) >> 6)
    varint_buf = buffer[:length]
    varint_buf[0] &= 0x3f
    return read(varint_buf, length), length * 8


def read_pn(buffer):
    pattern = (buffer[0] & 0xc0) >> 6
    if pattern == 0:
        length = 1
    elif pattern == 2:
        length = 2
    elif pattern == 3:
        length = 4
    else:
        raise ParseError('Unknown PN pattern {}'.format(pattern))

    pnbuf = buffer[:length]
    pnbuf[0] &= 0x3f

    return read(pnbuf, length), length * 8


def verify_condition(structure, field, formula):
    for f, v, _, _ in structure:
        if f == field:
            if 'eq' in formula:
                return v == formula['eq']
            elif 'neq' in formula:
                return v != formula['neq']
    return False
