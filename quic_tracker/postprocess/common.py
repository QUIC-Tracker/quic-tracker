functions = {}


def register(*scenarii):
    def inner(f):
        for s in scenarii:
            l = functions.get(s, [])
            l.append(f)
            functions[s] = l
        return f

    return inner

