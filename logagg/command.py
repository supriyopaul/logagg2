import os
import atexit

from basescript import BaseScript
from deeputil import AttrDict
import tornado.ioloop
import tornado.web
from kwikapi.tornado import RequestHandler
from kwikapi import API

from collector import LogCollector
from exceptions import InvalidArgument

class LogaggCommand(BaseScript):
    DESC = 'Logagg command line tool'

    def collect(self):
        master = AttrDict()
        try:
            master.host, master.port = self.args.master.split(":")
        except ValueError:
            raise InvalidArgument(self.args.master)

        collector = LogCollector(
            self.args.port,
            self.args.auth_key,
            self.args.auth_secret,
            self.args.data_path,
            master,
            self.log)
        collector._start()

        api = API()
        api.register(collector, 'v1')

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
                '--auth-key', '-k', required=True,
                help='Provide auth-key')
        collect_cmd.add_argument(
                '--auth-secret', '-s', required=True,
                help='Provide auth-secret')
        collect_cmd.add_argument(
                '--data-path', '-d', default=os.getcwd()+'/logagg-data',
                help= 'Data path for logagg, default: %(default)s')
        collect_cmd.add_argument(
                '--master', '-m', required=True,
                help= 'Master service to take commands from, <host:port>')

def main():
    LogaggCommand().start()

if __name__ == '__main__':
    main()
