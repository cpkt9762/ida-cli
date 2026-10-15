"""N6 search using the N0 traversal and result ordering."""
SEARCH_METHODS = ("search_bytes", "search_text", "search_imm", "search_instructions", "search_instruction_operands")


def byte_pattern(pattern):
    text = pattern.strip()
    if not text:
        raise ValueError("IDA error: empty pattern")
    if ' ' in text:
        tokens = text.split()
    else:
        if len(text.encode('utf-8')) % 2:
            raise ValueError('IDA error: invalid hex pattern length: '+text)
        tokens = [text[i:i+2] for i in range(0,len(text),2)]
    values = []
    import re
    for token in tokens:
        if token in ('?', '??'):
            values.append(None)
        else:
            digits = token
            while digits.startswith('0x'):
                digits = digits[2:]
            if not re.fullmatch(r'\+?[0-9a-fA-F]+', digits) or int(digits,16)>255:
                raise ValueError('IDA error: invalid byte: '+token)
            values.append(int(digits,16))
    return values


def invoke_search(method, params):
    import ida_bytes
    import ida_idaapi
    import ida_lines
    import ida_search
    import ida_segment
    import ida_ua
    import idautils
    import idc
    matches = []
    if method in ("search_text", "search_imm"):
        maximum = params.get("max_results",100)
        maximum = maximum if type(maximum) is int and 0<=maximum<2**64 else 100
        cursor = 0
        flags = ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT
        while True:
            if method == "search_text":
                text = params.get("text")
                text = text if isinstance(text,str) else ''
                ea = ida_search.find_text(cursor,0,0,text,flags) if '\0' not in text else ida_idaapi.BADADDR
            else:
                imm = params.get("imm",0)
                imm = imm if type(imm) is int and 0<=imm<2**64 else 0
                found = ida_search.find_imm(cursor,flags,imm & 0xffffffff)
                ea = found[0] if isinstance(found,tuple) else found
            if ea == ida_idaapi.BADADDR:
                break
            matches.append(hex(ea))
            if len(matches)>=maximum:
                break
            cursor = ida_search.find_defined(ea,flags) if method=="search_text" else ea
            if cursor==ida_idaapi.BADADDR:
                break
        return {"matches":matches,"count":len(matches)}
    patterns = params["patterns"]
    maximum = params.get("limit")
    maximum = 100 if maximum is None else maximum
    if method == "search_bytes":
        for pattern in patterns:
            try:
                pat = byte_pattern(pattern)
            except ValueError:
                if len(patterns)==1:
                    raise
                # This is the explicit N0 multi-pattern contract: invalid
                # patterns contribute no matches; a single invalid one errors.
                continue
            found = []
            for start in idautils.Segments():
                seg = ida_segment.getseg(start)
                offset, chunk = 0, 1024*1024
                while offset < seg.end_ea-start and len(found)<maximum:
                    remaining = seg.end_ea-start-offset
                    raw = ida_bytes.get_bytes(start+offset,min(remaining,chunk+len(pat)-1)) or b''
                    if len(raw)<len(pat): break
                    for i in range(len(raw)-len(pat)+1):
                        if len(found)>=maximum: break
                        if all(v is None or raw[i+j]==v for j,v in enumerate(pat)):
                            found.append(hex(start+offset+i))
                    if remaining<=chunk: break
                    offset+=chunk
                if len(found)>=maximum: break
            matches.extend(found)
        result = {"matches":matches,"count":len(matches)}
        if len(patterns)==1: result["pattern"]=patterns[0]
        return result
    if not patterns:
        raise ValueError("Invalid parameters: empty patterns")
    insensitive = params.get("case_insensitive")
    insensitive = True if insensitive is None else insensitive
    lower = lambda text: text.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')) if insensitive else text
    pats = [lower(p) for p in patterns]
    def line_at(ea):
        line = idc.generate_disasm_line(ea,0)
        if not line: return '', '', ''
        clean = ida_lines.tag_remove(line).split(';',1)[0].strip()
        parts = clean.split(None,1)
        return parts[0] if parts else '', parts[1].strip() if len(parts)>1 else '', clean
    def next_ea(ea):
        insn = ida_ua.insn_t()
        size = ida_ua.decode_insn(insn,ea)
        return min(2**64-1,ea+size) if size else ida_bytes.next_head(ea,ida_idaapi.BADADDR)
    def instruction_match(mnemonic,line,pat):
        return pat in lower(line if ' ' in pat or ',' in pat else mnemonic)
    for start in idautils.Segments():
        seg = ida_segment.getseg(start)
        cursor = start
        while cursor<seg.end_ea and len(matches)<maximum:
            mnemonic,operands,line = line_at(cursor)
            if mnemonic:
                if method=="search_instruction_operands":
                    if any(p in lower(operands) for p in pats):
                        matches.append({"address":hex(cursor),"mnemonic":mnemonic,"operands":operands,"line":line})
                elif instruction_match(mnemonic,line,pats[0]):
                    sequence,following=[cursor],cursor
                    for pat in pats[1:]:
                        following=next_ea(following)
                        if following>=seg.end_ea: break
                        m,_,clean=line_at(following)
                        if not m or not instruction_match(m,clean,pat): break
                        sequence.append(following)
                    if len(sequence)==len(pats):
                        match={"address":hex(cursor),"mnemonic":mnemonic,"line":line}
                        if len(pats)>1: match["sequence"]=[hex(ea) for ea in sequence]
                        matches.append(match)
            following=next_ea(cursor)
            if following<=cursor or following==ida_idaapi.BADADDR: break
            cursor=following
        if len(matches)>=maximum: break
    return {"patterns":patterns,"case_insensitive":insensitive,"matches":matches,"count":len(matches)}
