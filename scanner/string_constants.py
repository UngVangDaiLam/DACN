"""Conservative constant-string reversal within a single DEX basic block.

No APK code is executed. Never propagate values across CFG edges or unknown calls
that could mutate a StringBuffer/StringBuilder. Only report decoded literals used
as reflective class/method names, with original/decoded text and byte offsets.
"""
import re

BUILDERS = ('Ljava/lang/StringBuffer;', 'Ljava/lang/StringBuilder;')


def reversed_name_evidence(method):
    if not hasattr(method, 'get_basic_blocks'):
        return []
    findings = []
    for block in method.get_basic_blocks().gets():
        registers, pending = {}, None
        offset = block.get_start()
        for instruction in block.get_instructions():
            op = instruction.get_name()
            operands = instruction.get_operands()
            regs = [arg[1] for arg in operands if int(arg[0]) == 0]
            refs = [arg[2] for arg in operands if len(arg) >= 3 and isinstance(arg[2], str)]
            target = next((ref for ref in refs if '->' in ref), '')
            if op.startswith('const-string') and regs and refs:
                text = refs[-1]
                registers[regs[0]] = {'kind': 'string', 'text': text, 'original': text,
                                      'literal_offset': offset, 'operations': []} if len(text) <= 4096 else None
            elif op == 'new-instance' and regs:
                registers[regs[0]] = {'kind': 'builder', 'value': None} if any(ref in BUILDERS for ref in refs) else None
            elif op.startswith('move-result') and regs:
                registers[regs[0]], pending = pending, None
            elif op.startswith('move-object') and len(regs) == 2:
                registers[regs[0]] = registers.get(regs[1])
            elif op.startswith('invoke-'):
                pending = None
                builder = registers.get(regs[0]) if regs else None
                recognized = False
                if '/range' not in op and any(target.startswith(owner + '->') for owner in BUILDERS):
                    if '-><init>(Ljava/lang/String;)' in target and len(regs) == 2:
                        value = registers.get(regs[1])
                        if builder and builder.get('kind') == 'builder' and value and value.get('kind') == 'string':
                            builder['value'] = dict(value)
                            recognized = True
                    elif '->reverse()' in target and len(regs) == 1:
                        if builder and builder.get('kind') == 'builder':
                            value = builder.get('value')
                            if value:
                                builder['value'] = {**value, 'text': value['text'][::-1],
                                                    'operations': value['operations'] + [{'api': target, 'offset': offset}]}
                            pending, recognized = builder, True
                    elif '->toString()' in target and len(regs) == 1:
                        if builder and builder.get('kind') == 'builder':
                            pending, recognized = builder.get('value'), True
                if '/range' not in op:
                    index = 0 if target.startswith('Ljava/lang/Class;->forName(') else 1
                    use = target.startswith(('Ljava/lang/Class;->forName(',
                                             'Ljava/lang/Class;->getMethod(',
                                             'Ljava/lang/Class;->getDeclaredMethod('))
                    value = registers.get(regs[index]) if use and len(regs) > index else None
                    if (value and value.get('kind') == 'string' and value['operations']
                            and value['original'] != value['text']
                            and re.fullmatch(r'[A-Za-z_$][A-Za-z0-9_.$]*', value['text'])):
                        findings.append({'original': value['original'], 'decoded': value['text'],
                                         'literal_offset': value['literal_offset'],
                                         'operations': value['operations'], 'use_api': target,
                                         'use_offset': offset, 'scope': 'single_basic_block_constant_propagation'})
                if not recognized:
                    # Immutable strings stay valid; unknown calls may mutate builders.
                    for obj in registers.values():
                        if obj and obj.get('kind') == 'builder':
                            obj['value'] = None
            elif op == 'check-cast':
                pass
            elif regs:
                # Conservatively forget the first register for any unhandled operation.
                for reg in regs:
                    obj = registers.get(reg)
                    if obj and obj.get('kind') == 'builder':
                        obj['value'] = None
                registers[regs[0]] = None
                pending = None
            offset += instruction.get_length()
    return findings
