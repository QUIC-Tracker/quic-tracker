functions = {}


def register(*scenarii):
    def inner(f):
        for s in scenarii:
            l = functions.get(s, [])
            l.append(f)
            functions[s] = l
        return f

    return inner


host_to_name = {
    'quic.ogre.com:4433': 'ats',
    'minq.dev.mozaws.net:4433': 'minq',
    'mozquic.ducksong.com:4433': 'mozquic',
    'nghttp2.org:4433': 'ngtcp2',
    'quant.eggert.org:4433': 'quant',
    'kazuhooku.com:4433': 'quicly',
    'msquic.westus.cloudapp.azure.com:4433': 'winquic',
    'fb.mvfst.net:4433': 'mvfst',
    'pandora.cm.in.tum.de:4433': 'pandora',
    'quic.tech:4433': 'ngxquic',
    '208.85.208.226:4433': 'f5',
    'test.privateoctopus.com:4433':	'picoquic',
    'quicker.edm.uhasselt.be:4433': 'quicker',
    'ralith.com:4433': 'quicr',
    'xavamedia.nl:4433': 'quinn'
}
