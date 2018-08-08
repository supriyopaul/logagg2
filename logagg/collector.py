import sys
import time
import ujson as json
import glob
import uuid
import socket
import datetime
from operator import attrgetter
import traceback
from six import string_types as basestring
import six.moves.queue as queue
import re
import os
from os.path import isfile, join
from hashlib import md5

import shutil
from formatters import RawLog
from diskdict import DiskDict
from deeputil import AttrDict
from deeputil import keeprunning
from pygtail import Pygtail

from nsqsender import NSQSender
import util

def load_formatter_fn(formatter):
    '''
    >>> load_formatter_fn('logagg.formatters.basescript') #doctest: +ELLIPSIS
    <function basescript at 0x...>
    '''
    obj = util.load_object(formatter)
    if not hasattr(obj, 'ispartial'):
        obj.ispartial = util.ispartial
    return obj


class LogCollector(object):
    DESC = 'Collects the log information and sends to NSQTopic'

    QUEUE_MAX_SIZE = 2000                               # Maximum number of messages in in-mem queue
    MAX_NBYTES_TO_SEND = 4.5 * (1024**2)                # Number of bytes from in-mem queue minimally required to push
    MIN_NBYTES_TO_SEND = 512 * 1024                     # Minimum number of bytes to send to nsq in mpub
    MAX_SECONDS_TO_PUSH = 1                             # Wait till this much time elapses before pushing
    LOG_FILE_POLL_INTERVAL = 0.25                       # Wait time to pull log file for new lines added
    QUEUE_READ_TIMEOUT = 1                              # Wait time when doing blocking read on the in-mem q
    PYGTAIL_ACK_WAIT_TIME = 0.05                        # TODO: Document this
    SCAN_FPATTERNS_INTERVAL = 30                        # How often to scan filesystem for files matching fpatterns
    HOST = socket.gethostname()
    HEARTBEAT_RESTART_INTERVAL = 30                     # Wait time if heartbeat sending stops
    LOGAGGFS_FPATH_PATTERN = re.compile("[a-fA-F\d]{32}") # md5 hash pattern

    LOG_STRUCTURE = {
        'id': basestring,
        'timestamp': basestring,
        'file' : basestring,
        'host': basestring,
        'formatter' : basestring,
        'raw' : basestring,
        'type' : basestring,
        'level' : basestring,
        'event' : basestring,
        'data' : dict,
        'error' : bool,
        'error_tb' : basestring,
    }


    def __init__(self, port, auth_key, auth_secret, data_path, master, log):

        self.port = port
        self.auth_key = auth_key
        self.auth_secret = auth_secret
        self.data_path = util.ensure_dir(data_path)
        self.master = master

        self.log = log

        # For remembering the state of files
        self.state = DiskDict(data_path)
        # the mode on wich collector is running
        self.mode = self.state['mode'] or 'nofuse'

        self.logaggfs = AttrDict()
        # Initialize logaggfs paths
        if self.mode == 'fuse':
            self._init_logaggfs_paths()

        # Log fpath to thread mapping
        self.log_reader_threads = {}
        # Handle name to formatter fn obj map
        self.formatters = {}
        self.queue = queue.Queue(maxsize=self.QUEUE_MAX_SIZE)


    def _init_fpaths(self):
        self.state['fpaths'] = [{'fpath':'/var/log/serverstats/serverstats.log',
            'formatter':'logagg.formatters.docker_file_log_driver'}]
        self.state.flush()
        return self.state['fpaths']


    def _init_nsq_sender(self):
        self.nsq_sender = NSQSender(self.state['nsq_sender']['nsqd_http_address'],
                self.state['nsq_sender']['nsqtopic'],
                self.log)
        return self.nsq_sender


    def _init_logaggfs_paths(self):
        self.logaggfs.dir = self.state['logaggfs_dir']
        self.logaggfs.logs_dir = os.path.abspath(os.path.join(self.logaggfs.dir, 'logs'))
        self.logaggfs.trackfiles = os.path.abspath(os.path.join(self.logaggfs.dir, 'trackfiles.txt'))

    def _remove_redundancy(self, log):
        """Removes duplicate data from 'data' inside log dict and brings it
        out.

        >>> lc = LogCollector('file=/path/to/log_file.log:formatter=logagg.formatters.basescript', 30)

        >>> log = {'id' : 46846876, 'type' : 'log',
        ...         'data' : {'a' : 1, 'b' : 2, 'type' : 'metric'}}
        >>> lc._remove_redundancy(log)
        {'data': {'a': 1, 'b': 2}, 'type': 'metric', 'id': 46846876}
        """
        for key in log:
            if key in log and key in log['data']:
                log[key] = log['data'].pop(key)
        return log


    def _validate_log_format(self, log):
        '''
        >>> lc = LogCollector('file=/path/to/file.log:formatter=logagg.formatters.basescript', 30)

        >>> incomplete_log = {'data' : {'x' : 1, 'y' : 2},
        ...                     'raw' : 'Not all keys present'}
        >>> lc._validate_log_format(incomplete_log)
        'failed'

        >>> redundant_log = {'one_invalid_key' : 'Extra information',
        ...  'data': {'x' : 1, 'y' : 2},
        ...  'error': False,
        ...  'error_tb': '',
        ...  'event': 'event',
        ...  'file': '/path/to/file.log',
        ...  'formatter': 'logagg.formatters.mongodb',
        ...  'host': 'deepcompute-ThinkPad-E470',
        ...  'id': '0112358',
        ...  'level': 'debug',
        ...  'raw': 'some log line here',
        ...  'timestamp': '2018-04-07T14:06:17.404818',
        ...  'type': 'log'}
        >>> lc._validate_log_format(redundant_log)
        'failed'

        >>> correct_log = {'data': {'x' : 1, 'y' : 2},
        ...  'error': False,
        ...  'error_tb': '',
        ...  'event': 'event',
        ...  'file': '/path/to/file.log',
        ...  'formatter': 'logagg.formatters.mongodb',
        ...  'host': 'deepcompute-ThinkPad-E470',
        ...  'id': '0112358',
        ...  'level': 'debug',
        ...  'raw': 'some log line here',
        ...  'timestamp': '2018-04-07T14:06:17.404818',
        ...  'type': 'log'}
        >>> lc._validate_log_format(correct_log)
        'passed'
        '''

        keys_in_log = set(log)
        keys_in_log_structure = set(self.LOG_STRUCTURE)
        try:
            assert (keys_in_log == keys_in_log_structure)
        except AssertionError as e:
            self.log.warning('formatted_log_structure_rejected' ,
                                key_not_found = list(keys_in_log_structure-keys_in_log),
                                extra_keys_found = list(keys_in_log-keys_in_log_structure),
                                num_logs=1,
                                type='metric')
            return 'failed'

        for key in log:
            try:
                assert isinstance(log[key], self.LOG_STRUCTURE[key])
            except AssertionError as e:
                self.log.warning('formatted_log_structure_rejected' ,
                                    key_datatype_not_matched = key,
                                    datatype_expected = type(self.LOG_STRUCTURE[key]),
                                    datatype_got = type(log[key]),
                                    num_logs=1,
                                    type='metric')
                return 'failed'

        return 'passed'


    def _full_from_frags(self, frags):
        full_line = '\n'.join([l for l, _ in frags])
        line_info = frags[-1][-1]
        return full_line, line_info


    def _iter_logs(self, freader, fmtfn):
        # FIXME: does not handle partial lines
        # at the start of a file properly

        frags = []

        for line_info in freader:
            line = line_info['line'][:-1] # remove new line char at the end

            if not fmtfn.ispartial(line) and frags:
                yield self._full_from_frags(frags)
                frags = []

            frags.append((line, line_info))

        if frags:
            yield self._full_from_frags(frags)


    def _assign_default_log_values(self, fpath, line, formatter):
        '''
        >>> lc = LogCollector('file=/path/to/log_file.log:formatter=logagg.formatters.basescript', 30)
        >>> from pprint import pprint

        >>> formatter = 'logagg.formatters.mongodb'
        >>> fpath = '/var/log/mongodb/mongodb.log'
        >>> line = 'some log line here'

        >>> default_log = lc._assign_default_log_values(fpath, line, formatter)
        >>> pprint(default_log) #doctest: +ELLIPSIS
        {'data': {},
         'error': False,
         'error_tb': '',
         'event': 'event',
         'file': '/var/log/mongodb/mongodb.log',
         'formatter': 'logagg.formatters.mongodb',
         'host': '...',
         'id': None,
         'level': 'debug',
         'raw': 'some log line here',
         'timestamp': '...',
         'type': 'log'}
        '''
        return dict(
            id=None,
            file=fpath,
            host=self.HOST,
            formatter=formatter,
            event='event',
            data={},
            raw=line,
            timestamp=datetime.datetime.utcnow().isoformat(),
            type='log',
            level='debug',
            error= False,
            error_tb='',
          )


    @keeprunning(LOG_FILE_POLL_INTERVAL, on_error=util.log_exception)
    def _collect_log_lines(self, log_file):
        L = log_file
        fpath = L['fpath']
        fmtfn = L['formatter_fn']
        formatter = L['formatter']

        freader = Pygtail(fpath)
        for line, line_info in self._iter_logs(freader, fmtfn):
            log = self._assign_default_log_values(fpath, line, formatter)

            try:
                _log = fmtfn(line)

                if isinstance(_log, RawLog):
                    formatter, raw_log = _log['formatter'], _log['raw']
                    log.update(_log)
                    _log = load_formatter_fn(formatter)(raw_log)

                log.update(_log)
            except (SystemExit, KeyboardInterrupt) as e: raise
            except:
                log['error'] = True
                log['error_tb'] = traceback.format_exc()
                self.log.exception('error_during_handling_log_line', log=log['raw'])

            if log['id'] == None:
                log['id'] = uuid.uuid1().hex

            log = self._remove_redundancy(log)
            if self._validate_log_format(log) == 'failed': continue

            self.queue.put(dict(log=json.dumps(log),
                                freader=freader, line_info=line_info))
            self.log.debug('tally:put_into_self.queue', size=self.queue.qsize())

        while not freader.is_fully_acknowledged():
            t = self.PYGTAIL_ACK_WAIT_TIME
            self.log.debug('waiting_for_pygtail_to_fully_ack', wait_time=t)
            time.sleep(t)
        time.sleep(self.LOG_FILE_POLL_INTERVAL)


    def _get_msgs_from_queue(self, msgs, timeout):
        msgs_pending = []
        read_from_q = False
        ts = time.time()

        msgs_nbytes = sum(len(m['log']) for m in msgs)

        while 1:
            try:
                msg = self.queue.get(block=True, timeout=self.QUEUE_READ_TIMEOUT)
                read_from_q = True
                self.log.debug("tally:get_from_self.queue")

                _msgs_nbytes = msgs_nbytes + len(msg['log'])
                _msgs_nbytes += 1 # for newline char

                if _msgs_nbytes > self.MAX_NBYTES_TO_SEND:
                    msgs_pending.append(msg)
                    self.log.debug('msg_bytes_read_mem_queue_exceeded')
                    break

                msgs.append(msg)
                msgs_nbytes = _msgs_nbytes

                #FIXME condition never met
                if time.time() - ts >= timeout and msgs:
                    self.log.debug('msg_reading_timeout_from_mem_queue_got_exceeded')
                    break
                    # TODO: What if a single log message itself is bigger than max bytes limit?

            except queue.Empty:
                self.log.debug('queue_empty')
                time.sleep(self.QUEUE_READ_TIMEOUT)
                if not msgs:
                    continue
                else:
                    return msgs_pending, msgs_nbytes, read_from_q

        self.log.debug('got_msgs_from_mem_queue')
        return msgs_pending, msgs_nbytes, read_from_q


    @keeprunning(0, on_error=util.log_exception) # FIXME: what wait time var here?
    def _send_to_nsq(self, state):
        msgs = []
        should_push = False

        while not should_push:
            cur_ts = time.time()
            self.log.debug('should_push', should_push=should_push)
            time_since_last_push = cur_ts - state.last_push_ts

            msgs_pending, msgs_nbytes, read_from_q = self._get_msgs_from_queue(msgs,
                                                                        self.MAX_SECONDS_TO_PUSH)

            have_enough_msgs = msgs_nbytes >= self.MIN_NBYTES_TO_SEND
            is_max_time_elapsed = time_since_last_push >= self.MAX_SECONDS_TO_PUSH

            should_push = len(msgs) > 0 and (is_max_time_elapsed or have_enough_msgs)
            self.log.debug('deciding_to_push', should_push=should_push,
                            time_since_last_push=time_since_last_push,
                            msgs_nbytes=msgs_nbytes)

        try:
            if isinstance(self.nsq_sender, type(util.DUMMY)):
                for m in msgs:
                    self.log.info('final_log_format', log=m['log'])
            else:
                self.log.debug('trying_to_push_to_nsq', msgs_length=len(msgs))
                self.nsq_sender.handle_logs(msgs)
                self.log.debug('pushed_to_nsq', msgs_length=len(msgs))
            self._confirm_success(msgs)
            msgs = msgs_pending
            state.last_push_ts = time.time()
        except (SystemExit, KeyboardInterrupt): raise
        finally:
            if read_from_q: self.queue.task_done()


    def _confirm_success(self, msgs):
        ack_fnames = set()

        for msg in reversed(msgs):
            freader = msg['freader']
            fname = freader.filename

            if fname in ack_fnames:
                continue

            ack_fnames.add(fname)
            freader.update_offset_file(msg['line_info'])


    def _compute_fpatterns(self, f):

        # For every file in logaggfs logs directory compute 'md5*.log' pattern
        fpath = f.encode("utf-8")
        d = self.logaggfs.logs_dir
        dir_contents = [f for f in os.listdir(d) if bool(self.LOGAGGFS_FPATH_PATTERN.match(f)) and isfile(join(d, f))]
        dir_contents = set(dir_contents)
        for c in dir_contents:
            if md5(fpath).hexdigest() == c.split('.')[0]:
                return md5(fpath).hexdigest() + '*' + '.log'


    @keeprunning(SCAN_FPATTERNS_INTERVAL, on_error=util.log_exception)
    def _scan_fpatterns(self, state):
        '''
        For a list of given fpatterns or a logaggfs directory,
        this starts a thread collecting log lines from file

        >>> os.path.isfile = lambda path: path == '/path/to/log_file.log'
        >>> lc = LogCollector('file=/path/to/log_file.log:formatter=logagg.formatters.basescript', 30)

        >>> print(lc.fpaths)
        file=/path/to/log_file.log:formatter=logagg.formatters.basescript

        >>> print('formatters loaded:', lc.formatters)
        {}
        >>> print('log file reader threads started:', lc.log_reader_threads)
        {}
        >>> state = AttrDict(files_tracked=list())
        >>> print('files bieng tracked:', state.files_tracked)
        []


        >>> if not state.files_tracked:
        >>>     lc._scan_fpatterns(state)
        >>>     print('formatters loaded:', lc.formatters)
        >>>     print('log file reader threads started:', lc.log_reader_threads)
        >>>     print('files bieng tracked:', state.files_tracked)
        '''
        for f in self.state['fpaths']:

            if self.mode == 'fuse':
                fpattern, formatter = self._compute_fpatterns(f['fpath']), f['formatter']
                if fpattern == None: continue
                fpaths = glob.glob(join(self.logaggfs.logs_dir, fpattern))
            else:
                fpattern, formatter = f['fpath'], f['formatter']
                fpaths = glob.glob(fpattern)
                fpaths = list(set(fpaths) - set(state.files_tracked))
            self.log.debug('_scan_fpatterns', fpattern=fpattern, formatter=formatter, fpaths=fpaths)

            for fpath in fpaths:

                try:
                    formatter_fn = self.formatters.get(formatter,
                                  load_formatter_fn(formatter))
                    self.log.debug('found_formatter_fn', fn=formatter)
                    self.formatters[formatter] = formatter_fn
                except (SystemExit, KeyboardInterrupt): raise
                except (ImportError, AttributeError):
                    self.log.exception('formatter_fn_not_found', fn=formatter)
                    sys.exit(-1)
                # Start a thread for every file
                log_f = dict(fpath=fpath, fpattern=fpattern,
                                formatter=formatter, formatter_fn=formatter_fn)
                log_key = (fpath, fpattern, formatter)
                if log_key not in self.log_reader_threads:
                    self.log.info('starting_collect_log_lines_thread', log_key=log_key)
                    # There is no existing thread tracking this log file. Start one
                    log_reader_thread = util.start_daemon_thread(self._collect_log_lines, (log_f,))
                    self.log_reader_threads[log_key] = log_reader_thread
                state.files_tracked.append(fpath)
        time.sleep(self.SCAN_FPATTERNS_INTERVAL)


    @keeprunning(HEARTBEAT_RESTART_INTERVAL, on_error=util.log_exception)
    def _send_heartbeat(self, state):

        # Sends continuous heartbeats to a seperate topic in nsq
        if self.log_reader_threads:
            for f in self.log_reader_threads:
                files_tracked = self.log_reader_threads.keys()
        else:
            files_tracked = ''

        heartbeat_payload = {'host': self.HOST,
                            'heartbeat_number': state.heartbeat_number,
                            'timestamp': time.time(),
                            'nsq_topic': self.nsq_sender.topic_name,
                            'files_tracked': files_tracked
                            }
        self.nsq_sender.handle_heartbeat(heartbeat_payload)
        state.heartbeat_number += 1
        time.sleep(self.HEARTBEAT_RESTART_INTERVAL)


    def _collect(self):

        # start tracking files and put formatted log lines into queue
        state = AttrDict(files_tracked=list())
        util.start_daemon_thread(self._scan_fpatterns, (state,))

        # start extracting formatted logs from queue and send to nsq
        state = AttrDict(last_push_ts=time.time())
        util.start_daemon_thread(self._send_to_nsq, (state,))

        # start sending heartbeat to "Hearbeat" topic
        state = AttrDict(heartbeat_number=0)
        self.log.info('init_heartbeat')
        th_heartbeat = util.start_daemon_thread(self._send_heartbeat, (state,))


    def _start(self):

        # Add initial files i.e. serverstats to state
        if not self.state['fpaths']:
            self.log.info('init_fpaths')
            self._init_fpaths()

        # Create nsq_sender
        if self.state['nsq_sender']:
            self.log.info('init_nsq_sender')
            self._init_nsq_sender()

        self._collect()


    def _add_to_logaggfs_trackfile(self, fpath):

        # Given a fpath add it to logaggfs trackfiles.txt via moving
        tmpfile = open('/tmp/trackfiles.txt', 'w+')

        with open(self.logaggfs.trackfiles, 'r') as f:
            tmpfile.write(f.read() + fpath + '\n')
        tmpfile.close()

        shutil.move('/tmp/trackfiles.txt', self.logaggfs.trackfiles)


    def _remove_from_logaggfs_trackfile(self, fpath):

        # Given a fpath remove it from logaggfs trackfiles.txt via moving
        tmpfile = open('/tmp/trackfiles.txt', 'w+')

        with open(self.logaggfs.trackfiles, 'r') as f:
            paths = [line[:-1] for line in f.readlines()]

        for p in paths:
            if p == fpath: pass
            else: tmpfile.write(p + '\n')

        shutil.move('/tmp/trackfiles.txt', self.logaggfs.trackfiles)
        tmpfile.close()


    def add_file(self, fpath:str, formatter:str) -> list:

        f = {"fpath":fpath, "formatter":formatter}

        # Add new file to logaggfs trackfiles.txt
        if self.mode == 'fuse':
            self._add_to_logaggfs_trackfile(f['fpath'])

        # Add new file to state
        s = self.state['fpaths']
        s.append(f)
        self.state['fpaths'] = self.fpaths = s
        self.state.flush()

        return self.state['fpaths']


    def get_files(self) -> list:

        # List of files to be tracked by collector
        return self.state['fpaths']


    def set_nsq(self, nsqd_http_address:str, topic:str) -> dict:

        # Store nsq details in state in disk-dict
        self.state['nsq_sender'] = {'nsqd_http_address': nsqd_http_address,
                'nsqtopic': topic}
        self.state.flush()
        self.log.info('exiting', fpaths=self.state['nsq_sender'])
        self.log.info('restart_for_changes_to_take_effect')
        sys.exit(0)


    def get_nsq(self) -> dict:
        return self.state['nsq_sender']


    def get_active_log_collectors(self) -> list:

        # return the files on which active threads are running to collect logs
        collectors = self.log_reader_threads
        c = [t[0] for t in collectors if collectors[t].isAlive()]
        return c


    def remove_file(self, fpath:str) -> dict:
        #FIXME: stops the program after removing

        # Remove fpath from logaggfs trackfile.txt
        self._remove_from_logaggfs_trackfile(fpath)

        # Remove fpath from state
        s = list()
        for f in self.state['fpaths']:
            if f['fpath'] == fpath: pass
            else: s.append(f)

        self.state['fpaths'] = s
        self.state.flush()
        self.log.info('exiting', fpaths=self.state['fpaths'])
        self.log.info('restart_for_changes_to_take_effect')
        sys.exit(0)


    def set_logaggfs_dir(self, directory:str) -> dict:
        #FIXME: stops the program after updating

        # Store logaggfs directory to state file
        self.state['logaggfs_dir'] = directory

        # Change mode to fuse
        self.state['mode'] = 'fuse'
        self.state.flush()
        self.log.info('exiting', mode=self.state['mode'])
        self.log.info('restart_for_changes_to_take_effect')
        sys.exit(0)


    def get_mode(self) -> dict:
        if self.state['mode'] == 'fuse':
            return dict(mode=self.state['mode'], logaggfs_dir=self.state['logaggfs_dir'])
        else:
            return dict(mode=self.mode)

