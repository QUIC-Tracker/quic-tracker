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

import json
import os
from base64 import b64decode

from quic_tracker.dissector import parse_packet
from quic_tracker.utils import split_every_n, join_root

_trace = {"commit":"89878dc3247ea3da1b3d7a077de1e49e2e2568d6","scenario":"flow_control","scenario_version":1,"host":"quic.ogre.com:4433","ip":"23.253.107.52","results":{"error":"read udp4 192.168.1.105:55730-\u003e23.253.107.52:4433: i/o timeout"},"started_at":1520076590,"duration":10000,"error_code":5,"stream":[{"direction":"to_server","timestamp":152007659064,"data":"/07tjIoK0kdb/wAACQrSR1wSAEJ/FgMDAnoBAAJ2AwP5qER/LB/2KBW+7zSEXxXTNAn8r0SbkdfTpTdC8HFWqgAABBMBEwIBAAJJACsAAwJ/FwAAABIAEAAADXF1aWMub2dyZS5jb20AMwHUAdIAFwBBBPP+Ebb+3OTRZbcEsPEKcEDXG0yXPMPRioHAp41Kvqo1+L7En8LcB/tIqpZ7yKQzirSjcDY/7Vcf6/mgHdam9YsAGABhBNRtKnLxesCYn2JNNBkXd3zTlyNdhcFHZqzIzpCw2fk8KVVhv39bwk3k9QcqWkQPWRXHmuXqRwTmSCyMBPbT9q4aR3tCc0aoRsYTQuUPDbU/S+GZ4ZZTx5tx7FooBb3vAAEAAQB5+11GZX/YWAdaJ9DcTvbZcRbGD3SXMQIeQdOsC4uZUKqOlu/SYeucLw39+gO88HfHWDXKettP0yHEQPN9LHDho10WWyoea0nUk4QNfwCOEcowJiQcB4tKXDnER0pJw4+oRo802dMCLIfkiLSfU8gB0K3iXfn/CbIp5JPG8taUcOtNid7/zelciDbHAeDKwMZnC3+36PN+uje3BkoSQxrOsZVhl2YTSoI35stFc+g6n7MgsdAboNveYqrT5OKdz++/XRPAzJdAA/6UAEcRYTX5tSF4JqO291G7koxCZxnFw8ily5mRUON4+iz5fgFcAo9zKSq3uNeuAgDEIrFyFyu4AB0AIBQpvCs+8wnHVb2ztZvjgZuCDEowHDiekZTHIl9s3ocMAAoACgAIABcAGAEAAB0ADQAOAAwIBAgFCAYEAwUDBgMAEAAIAAYFaHEtMDkAGgAk/wAACQAeAAAABAAAAFAAAQAEAACAAAACAAQAAAARAAMAAgAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},{"direction":"to_client","timestamp":152007659096,"data":"/axhrMd6PTZC/wAACRus0boOitJHXEJoAAASAETEFgMDAHsCAAB3AwOsHYNHBpAMsXgDMzU9NmRWBwEEe4xku4E7+b7mCu1VpAATAQAATwArAAJ/FwAzAEUAFwBBBA8RjG2gq03zjuAkHcmhAZTG0wsVdEh6Zigk5hSXdkA5dF2xhEnrEZnccf21utM6+RypreJyLYejkNAHObcJJzkUAwMAAQEXAwMAerP8JUukdtTX+1zn8r69/1+pFkYWGgwPgi4gi6FIlFQJrBiBgazQZ5gBVWVXHIe89xSwJ4/mI3SLRDCNv0ThYB46tVKJfyFzA36dkRWbo7wVkH7bHkdRIA6GVy+LSslo11S1Mvh+CTipT+RfqCmhDV9XWOWydychbT3/FwMDBVTFxn2DcMlY05MApcbcBoyMH2na+338pL13LoQNMhblGMFaGFNQkSwYZ/rOI13iOeytKq9wI7fmkkhmnk5Wc7KmNeLjtVmdSyXNFSy0mtslw8FqCv+3XIPuX4FmMTzG2Pjb9lFF5AEBQGAbgQghKUdyy8Do7zZns2PJT7otiuJ0eWo6uun/hVdtMU/bndyewOmxNzHPhd4WoWOTw9ZPkMdxYSqlbOaHO2t02/vur6trmYnFzaWhRSwJZVaE8yGi36MBV51HR2k7QXqOE0LYmEXkXHp9wD9cNepdG8dDvdQv+c2hBamu6GihAmP8IHH1MclV73sYVExEZMCzOP2RJQrcNg3VSi/AY/P5S2VDiHCn+EJn4dqdrB0K1sbPc7VP6D+XDSO+4IvCdEMACHoIsEqG7OOjI/AShcZ4+Mi+ip40uSm54DnCJfiQih4QXCI4CVG72r76favpuHb7jN7vkyXvTyPqugX8aL6h00xLGuS6w+Lu5TLs/fnd+ZiWCRuNtG9HdOwN91vZ+J+VcF2kc5V10djvHdBErP/i9izQLdpcPms5Xbux7JVZnonp1QS6zVEQnWUbYmNCv4ZV+0CYw1e8bIiMtXJsQuBxsW2SSLTDsd51SMMiuA0K2IvPglyKNCJjXwCtu77Kf4JvC2LlZjy290wwex60rWX3Zqum7/RR8kOkF1InYDPr488+qV9gyc+mgCczkIk1J9S8owfaprNK5yyAWAR+HM0DbQcu+YeSB2vmrHR+hUmfTGLiceKc6a5jQTQOXGRXRWWm4absJlyrLq0xYxM8iSm6yyHsvRsn9lOIH3vEx6ESbMe3QKSXMceWzFc89SS4NTBBVd2FwyK3NsmbnKKeUUauhdM6JdXrT9RJYmMN1MNsTewGAPfluVxyljkUO9PlzNb3tbJwCLPAs1Omg5tPy8LvtzsvFxcnHqopHDdAlHUuoiufk/nEQpxt1gR02f/BAzNB+3NudE5yKXpx0MGfmbuHFDTnAoG/wk/st5wCsbN/u0xxpOvMVEljCZs+jVnmlF1UfLQKs/XHTdRMmXakDaFJfh0HLUCChBJWK02nR7E+9CG88F5Ze3rCYJz4wk4rXxctsuwwqKlkiVeLiOwempyBACxJnXFkAcF0X3tR9ST4mRxTsNcd/Pfo0wIDjPVPEjpzAvEpk24gilrLvHQcUttnUr5cjbvkJq2ApM+qerllekOc+VfIrRVHn3+6OdFJqgSUsk+gdZUR9tlTbwuNibFmiC9Cybx5bqC+OFByuViX38k="},{"direction":"to_server","timestamp":152007659097,"data":"/axhrMd6PTZC/wAACQrSR10Om6zRugAAAA=="},{"direction":"to_client","timestamp":152007659097,"data":"/axhrMd6PTZC/wAACRus0bsWAETEQvKbudLURMv/CFT6cZ3PH5E4dbhzjc1YFQiQhaene9LKgVFbmzvj0YDSCjZrwuHR9tk0GHinvN/oJmIb4/oyltF1Xv3uV8MEMxUJgGuIO03z8YX297mgYKPuI561iaYgCfSlEpdXA3IzHVnKr3L7ycKsgbyU+YDZLAqYu7KV38u8ZLZtmYZOhsLAwfrdIuipsPp2NA7IJmRnIrJcn7GIPhteOttDsPZfC5tjgCI6Vpf0j4+dnGcJi17hcv8dkAcQfK5I0zmi7yH3eC3n6gW9BMDbO9nzByxNTdf5PaF/Q8IfMS5wOzSgkyB+y7KD6UpeitdDlKz/YVs57W5zp+eU/slvHUpL4x4ogDGmhoyQK7C2XbvIA6JbkoSH5N7AzFH+BZzSw3pcBDBrkGg/82jTkP/ig+jDURgAI/ngtUdHQsRdsi6ND3M9J14I68GJ5sDjb06UZxfaeiqrI0SVou/hwakEoOnG7L8wYyNY51t6yExIHPi59FCaK+Cp4+rKRlvGTSVwBM+crGY3LZd80kJvZAgZSkuLqIsvsRDd0hcDAwEZPyT1/2ovSTCJN6P/iwcatMPFszzDrJkR+T6HCfKFfR5/8SnH9uttWBluP9FJLy3+g/lkKMBtP190HAgoWRVaL4ZKxuk7Gzmv58nkj5CkEv1vfrE4Fizd82v4WVbFDb94ZbgpWG8bXap4PuwSucmfcxMtzUjChPtG5A+Z/XHCbEWgOAtkOAwy8l3PJ1P56m84PHie5mriIhjBOTVRJ9vLFO6Ty8Ig0ThYHYtnyQi5LNJpj+FrnP91HM3GB/uZjo+FClFldG7+W8pouWrIEpxfiOYAyNpMFyqpxVv2i0w8ffvTg0CEL+ANtn6tynprGEK8QXYcyoyitwYXr7z34HOPNErgpVbuJM7vouO+w8Fas+RJOuMXXdyYO9EXAwMANcl+GAx+aHxQd3mJou254g4LsFiX3EeADMpuyolEBlEiA8VeFnzEfDxYofEtwH5CK9NtXM1v"},{"direction":"to_server","timestamp":152007659097,"data":"/axhrMd6PTZC/wAACQrSR14WAEJ/OhcDAwA12He1ark9hawn3Cm1iHPS0bM3qbmTDJ5yaizIIPzJ6yXs7FYxqaJFO6aR9Hjd+Xig+pORPj4Om6zRuwAAAQ=="},{"direction":"to_server","timestamp":152007659097,"data":"HaxhrMd6PTZCCtJHXxIEB0dFVCAvDQoOm6zRuwAAAQ=="},{"direction":"to_client","timestamp":152007659115,"data":"/axhrMd6PTZC/wAACRus0bwSAETEFgMDAHsCAAB3AwOsHYNHBpAMsXgDMzU9NmRWBwEEe4xku4E7+b7mCu1VpAATAQAATwArAAJ/FwAzAEUAFwBBBA8RjG2gq03zjuAkHcmhAZTG0wsVdEh6Zigk5hSXdkA5dF2xhEnrEZnccf21utM6+RypreJyLYejkNAHObcJJzkUAwMAAQEXAwMAerP8JUukdtTX+1zn8r69/1+pFkYWGgwPgi4gi6FIlFQJrBiBgazQZ5gBVWVXHIe89xSwJ4/mI3SLRDCNv0ThYB46tVKJfyFzA36dkRWbo7wVkH7bHkdRIA6GVy+LSslo11S1Mvh+CTipT+RfqCmhDV9XWOWydychbT3/FwMDBVTFxn2DcMlY05MApcbcBoyMH2na+338pL13LoQNMhblGMFaGFNQkSwYZ/rOI13iOeytKq9wI7fmkkhmnk5Wc7KmNeLjtVmdSyXNFSy0mtslw8FqCv+3XIPuX4FmMTzG2Pjb9lFF5AEBQGAbgQghKUdyy8Do7zZns2PJT7otiuJ0eWo6uun/hVdtMU/bndyewOmxNzHPhd4WoWOTw9ZPkMdxYSqlbOaHO2t02/vur6trmYnFzaWhRSwJZVaE8yGi36MBV51HR2k7QXqOE0LYmEXkXHp9wD9cNepdG8dDvdQv+c2hBamu6GihAmP8IHH1MclV73sYVExEZMCzOP2RJQrcNg3VSi/AY/P5S2VDiHCn+EJn4dqdrB0K1sbPc7VP6D+XDSO+4IvCdEMACHoIsEqG7OOjI/AShcZ4+Mi+ip40uSm54DnCJfiQih4QXCI4CVG72r76favpuHb7jN7vkyXvTyPqugX8aL6h00xLGuS6w+Lu5TLs/fnd+ZiWCRuNtG9HdOwN91vZ+J+VcF2kc5V10djvHdBErP/i9izQLdpcPms5Xbux7JVZnonp1QS6zVEQnWUbYmNCv4ZV+0CYw1e8bIiMtXJsQuBxsW2SSLTDsd51SMMiuA0K2IvPglyKNCJjXwCtu77Kf4JvC2LlZjy290wwex60rWX3Zqum7/RR8kOkF1InYDPr488+qV9gyc+mgCczkIk1J9S8owfaprNK5yyAWAR+HM0DbQcu+YeSB2vmrHR+hUmfTGLiceKc6a5jQTQOXGRXRWWm4absJlyrLq0xYxM8iSm6yyHsvRsn9lOIH3vEx6ESbMe3QKSXMceWzFc89SS4NTBBVd2FwyK3NsmbnKKeUUauhdM6JdXrT9RJYmMN1MNsTewGAPfluVxyljkUO9PlzNb3tbJwCLPAs1Omg5tPy8LvtzsvFxcnHqopHDdAlHUuoiufk/nEQpxt1gR02f/BAzNB+3NudE5yKXpx0MGfmbuHFDTnAoG/wk/st5wCsbN/u0xxpOvMVEljCZs+jVnmlF1UfLQKs/XHTdRMmXakDaFJfh0HLUCChBJWK02nR7E+9CG88F5Ze3rCYJz4wk4rXxctsuwwqKlkiVeLiOwempyBACxJnXFkAcF0X3tR9ST4mRxTsNcd/Pfo0wIDjPVPEjpzAvEpk24gilrLvHQcUttnUr5cjbvkJq2ApM+qerllekOc+VfIrRVHn3+6OdFJqgSUsk+gdZUR9tlTbwuNibFmiC9Cybx5bqC+OFByuViX38k="},{"direction":"to_server","timestamp":152007659115,"data":"HaxhrMd6PTZCCtJHYA6brNG8AAAC"},{"direction":"to_client","timestamp":152007659115,"data":"/axhrMd6PTZC/wAACRus0b0WAETEQvKbudLURMv/CFT6cZ3PH5E4dbhzjc1YFQiQhaene9LKgVFbmzvj0YDSCjZrwuHR9tk0GHinvN/oJmIb4/oyltF1Xv3uV8MEMxUJgGuIO03z8YX297mgYKPuI561iaYgCfSlEpdXA3IzHVnKr3L7ycKsgbyU+YDZLAqYu7KV38u8ZLZtmYZOhsLAwfrdIuipsPp2NA7IJmRnIrJcn7GIPhteOttDsPZfC5tjgCI6Vpf0j4+dnGcJi17hcv8dkAcQfK5I0zmi7yH3eC3n6gW9BMDbO9nzByxNTdf5PaF/Q8IfMS5wOzSgkyB+y7KD6UpeitdDlKz/YVs57W5zp+eU/slvHUpL4x4ogDGmhoyQK7C2XbvIA6JbkoSH5N7AzFH+BZzSw3pcBDBrkGg/82jTkP/ig+jDURgAI/ngtUdHQsRdsi6ND3M9J14I68GJ5sDjb06UZxfaeiqrI0SVou/hwakEoOnG7L8wYyNY51t6yExIHPi59FCaK+Cp4+rKRlvGTSVwBM+crGY3LZd80kJvZAgZSkuLqIsvsRDd0hcDAwEZPyT1/2ovSTCJN6P/iwcatMPFszzDrJkR+T6HCfKFfR5/8SnH9uttWBluP9FJLy3+g/lkKMBtP190HAgoWRVaL4ZKxuk7Gzmv58nkj5CkEv1vfrE4Fizd82v4WVbFDb94ZbgpWG8bXap4PuwSucmfcxMtzUjChPtG5A+Z/XHCbEWgOAtkOAwy8l3PJ1P56m84PHie5mriIhjBOTVRJ9vLFO6Ty8Ig0ThYHYtnyQi5LNJpj+FrnP91HM3GB/uZjo+FClFldG7+W8pouWrIEpxfiOYAyNpMFyqpxVv2i0w8ffvTg0CEL+ANtn6tynprGEK8QXYcyoyitwYXr7z34HOPNErgpVbuJM7vouO+w8Fas+RJOuMXXdyYO9EXAwMANcl+GAx+aHxQd3mJou254g4LsFiX3EeADMpuyolEBlEiA8VeFnzEfDxYofEtwH5CK9NtXM1v"},{"direction":"to_server","timestamp":152007659115,"data":"HaxhrMd6PTZCCtJHYQ6brNG9AAAD"},{"direction":"to_client","timestamp":152007659122,"data":"H6xhrMd6PTZCvg6K0kdfHgACFgBHtkDwFwMDAOv9U3XfW+LMSMOmKDEEOU9qgTYGCdJpfWjbwnmnsYW9L70nL53daZI96eC453FGa4JlBZnIDtuaw080iidv1DJdVrlu+8+3Ol/PiHOpvbtk3QPXRVd/NI65hEtzAEoAtgvQxmQSc4ktLrd1256PACng3kxlDTgeMZqJawd/FCALQ9GHOdvj+hR0wPQV3NxrLiqKUtM+XelLzDCL33/5jqdQFlbIXKJ6VDiP79piU0QeLWZe5BKIeUKwYF1oonKgTgrATC6MRZU5NbBFnSbMBkUgs/hbwIN7ek3mjINvjYqp95vdXZ2VmhYpFm3jCwDx9uqNHEwTeAxhWsGvtjz2V0la/0LyvQcLAcxpatnVEmBwthD5s+ZKQuCml7T3x+5qRAsCO/HV9zKfeC7JnqJQMlYriXbfSlYsbaZN"},{"direction":"to_server","timestamp":152007659122,"data":"HaxhrMd6PTZCCtJHYg6brNG+AAAE"},{"direction":"to_client","timestamp":152007659122,"data":"H6xhrMd6PTZCvwkEQFASBEBQPCFET0NUWVBFIEhUTUwgUFVCTElDICItLy9JRVRGLy9EVEQgSFRNTCAyLjAvL0VOIj4KPGh0bWw+PGhlYWQ+Cjx0aXRsZT4zMDIgRm91bmQ="},{"direction":"to_server","timestamp":152007659122,"data":"HaxhrMd6PTZCCtJHYw6brNG/AAAF"}]}


def parse_trace(trace):
    trace['stream'] = (trace['stream'] or [])[:100]
    context = {}
    for packet in trace['stream']:
        packet['data'] = bytearray(b64decode(packet['data']))
        if packet['direction'] not in context:
            context[packet['direction']] = {}
        packet['dissection'] = parse_packet(packet['data'], context[packet['direction']])
        packet['length'] = len(packet['data'])
        packet['type'] = get_type(packet['dissection'][1])
        packet['number'] = get_number_packet(packet)
        packet['data'] = split_every_n(packet['data'].hex())
    return trace


def get_type(packet):  # TODO: Modularise this on a per version basis
    top_struct_attributes = packet[0][1][1]
    for field, value, _, _ in top_struct_attributes:
        if field == 'Header Form' and value == 0:
            return '1-RTT Protected Payload'
        elif field == 'Long Packet Type':
            value = int(value, base=0)
            if value == 0x7f:
                return 'Initial'
            elif value == 0x7e:
                return 'Retry'
            elif value == 0x7d:
                return 'Handshake'
            elif value == 0x7c:
                return '0-RTT Protected'
    return 'Version Negotiation'


def get_number_packet(packet):
    if packet['type'] == 'Version Negotiation':
        return 0

    top_struct_attributes = packet['dissection'][1][0][1][1]
    for field, value, _, _ in top_struct_attributes:
        if field == 'Packet Number':
            return value

    return None


def get_traces(trace_id):
    file_path = join_root('traces', str(trace_id) + os.extsep + 'json')
    if not os.path.exists(file_path):
        return None
    with open(file_path) as f:
        return json.load(f)


def find_similar_trace_idx(trace, traces):
    for i, t in enumerate(traces or []):
        if t['host'] == trace['host'] and t['scenario'] == trace['scenario']:
            return i
