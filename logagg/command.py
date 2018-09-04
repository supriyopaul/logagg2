import os

from basescript import BaseScript
from deeputil import AttrDict
import tornado.ioloop
import tornado.web
from kwikapi.tornado import RequestHandler
from kwikapi import API

from collector import LogCollector, CollectorService
from exceptions import InvalidArgument

class LogaggCommand(BaseScript):
    DESC = 'Logagg command line tool'

    def collect(self):
        master = AttrDict()
        try:
            m = self.args.master.split(':')
            # So that order of keys is not a factor
            for a in m:
                a = a.split('=')
                if a[0] == 'host': master.host = a[-1]
                elif a[0] == 'port': master.port = a[-1]
                elif a[0] == 'key': master.key = a[-1]
                elif a[0] == 'secret': master.secret = a[-1]
                else: raise ValueError

        except ValueError:
            raise InvalidArgument(self.args.master)

        # Create collector object
        collector = LogCollector(
            self.args.data_dir,
            self.args.logaggfs_dir,
            master,
            self.log)

        collector_api = CollectorService(collector, self.log)
        api = API()
        api.register(collector_api, 'v1')

        app = tornado.web.Application([
            (r'^/logagg/.*', RequestHandler, dict(api=api)),
                ])

        app.listen(self.args.port)
        tornado.ioloop.IOLoop.current().start()

    def define_subcommands(self, subcommands):
        super(LogaggCommand, self).define_subcommands(subcommands)

        collect_cmd = subcommands.add_parser('collect',
                help='Collects the logs from different files and sends to nsq')
        collect_cmd.set_defaults(func=self.collect)
        collect_cmd.add_argument(
                '--port', '-p', default=1099,
                help='port to run logagg collector service on, default: %(default)s')
        collect_cmd.add_argument(
                '--master', '-m', required=True,
                help= 'Master service details, format: <host=localhost:port=1100:key=xyz:secret=xxxx>')
        collect_cmd.add_argument(
                '--data-dir', '-d', default=os.getcwd()+'/logagg-data',
                help= 'Data path for logagg, default: %(default)s')
        collect_cmd.add_argument(
                '--logaggfs-dir', '-l', default='/logcache',
                help= 'LogaggFS directory, default: %(default)s')

def main():
    LogaggCommand().start()

if __name__ == '__main__':
    main()
