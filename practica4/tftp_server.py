import socket, os, time
import select
import threading
from tftpy.TftpShared import *
from tftpy.TftpPacketTypes import *
from tftpy.TftpPacketFactory import TftpPacketFactory
from tftpy.TftpContexts import TftpContextServer


class TftpServer(TftpSession):
    def __init__(self, tftproot='.', dyn_file_func=None):
        self.listenip = None
        self.listenport = None
        self.sock = None
        self.root = os.path.abspath(tftproot)
        self.dyn_file_func = dyn_file_func
        # A dict of sessions, where each session is keyed by a string like
        # ip:tid for the remote end.
        self.sessions = {}
        # A threading event to help threads synchronize with the server
        # is_running state.
        self.is_running = threading.Event()

        self.shutdown_gracefully = False
        self.shutdown_immediately = False

        if self.dyn_file_func:
            if not callable(self.dyn_file_func):
                raise TftpException("A dyn_file_func supplied, but it is not callable.")
        elif os.path.exists(self.root):
            log.debug("tftproot %s does exist", self.root)
            if not os.path.isdir(self.root):
                raise TftpException("The tftproot must be a directory.")
            else:
                log.debug("tftproot %s is a directory", self.root)
                if os.access(self.root, os.R_OK):
                    log.debug("tftproot %s is readable", self.root)
                else:
                    raise TftpException("The tftproot must be readable")
                if os.access(self.root, os.W_OK):
                    log.debug("tftproot %s is writable", self.root)
                else:
                    log.warning("The tftproot %s is not writable" % self.root)
        else:
            raise TftpException("The tftproot does not exist.")

    def listen(self,
               listenip="127.0.0.1",
               listenport=DEF_TFTP_PORT,
               timeout=SOCK_TIMEOUT):
        """Start a server listening on the supplied interface and port. This
        defaults to INADDR_ANY (all interfaces) and UDP port 69. You can also
        supply a different socket timeout value, if desired."""
        tftp_factory = TftpPacketFactory()
        if not listenip: listenip = '0.0.0.0'
        log.info("Server requested on ip %s, port %s"
                 % (listenip, listenport))
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP mode 0w0
            self.sock.bind((listenip, listenport))
            _, self.listenport = self.sock.getsockname()
        except socket.error as err:
            # Reraise it for now.
            raise

        self.is_running.set()

        log.info("Recepcion")
        while True:
            if self.shutdown_immediately:
                log.warn("Shutting down now. Session count: %d" % len(self.sessions))
                self.sock.close()
                for key in self.sessions:
                    self.sessions[key].end()
                self.sessions = []
                break

            elif self.shutdown_gracefully:
                if not self.sessions:
                    log.warn("In graceful shutdown mode and all sessions complete.")
                    self.sock.close()
                    break

            # Build the inputlist array of sockets to select() on.
            inputlist = [self.sock]
            for key in self.sessions:
                inputlist.append(self.sessions[key].sock)

            # Block until some socket has input on it.
            log.debug("Performing select on this inputlist: %s", inputlist)
            readyinput, readyoutput, readyspecial = select.select(inputlist,
                                                                  [],
                                                                  [],
                                                                  SOCK_TIMEOUT)

            deletion_list = []

            # Handle the available data, if any. Maybe we timed-out.
            for readysock in readyinput:
                # Is the traffic on the main server socket? ie. new session?
                if readysock == self.sock:
                    log.debug("Data ready on our main socket")
                    buffer, (raddress, rport) = self.sock.recvfrom(MAX_BLKSIZE)
                    log.debug("Cliente:" + raddress + ":" + str(rport))
                    log.debug("Read %d bytes", len(buffer))

                    if self.shutdown_gracefully:
                        log.warn("Discarding data on main port, in graceful shutdown mode")
                        continue

                    # Forge a session key based on the client's IP and port,
                    # which should safely work through NAT.
                    key = "%s:%s" % (raddress, rport)
                    if not key in self.sessions:
                        log.debug("Creating new server context for "
                                  "session key = %s", key)
                        self.sessions[key] = TftpContextServer(raddress,
                                                               rport,
                                                               timeout,
                                                               self.root,
                                                               self.dyn_file_func)
                        try:
                            self.sessions[key].start(buffer)
                        except TftpException as err:
                            deletion_list.append(key)
                            log.error("Fatal exception thrown from "
                                      "session %s: %s" % (key, str(err)))
                    else:
                        log.warn("received traffic on main socket for "
                                 "existing session??")
                    log.info("Currently handling these sessions:")
                    for session_key, session in self.sessions.items():
                        log.info("    %s" % session)

                else:
                    # Must find the owner of this traffic.
                    for key in self.sessions:
                        if readysock == self.sessions[key].sock:
                            log.info("Matched input to session key %s"
                                     % key)
                            try:
                                self.sessions[key].cycle()
                                if self.sessions[key].state == None:
                                    log.info("Successful transfer.")
                                    deletion_list.append(key)
                            except TftpException as err:
                                deletion_list.append(key)
                                log.error("Fatal exception thrown from "
                                          "session %s: %s"
                                          % (key, str(err)))
                            # Break out of for loop since we found the correct
                            # session.
                            break

                    else:
                        log.error("Can't find the owner for this packet. "
                                  "Discarding.")

            log.debug("Looping on all sessions to check for timeouts")
            now = time.time()
            for key in self.sessions:
                try:
                    self.sessions[key].checkTimeout(now)
                except TftpTimeout as err:
                    log.error(str(err))
                    self.sessions[key].retry_count += 1
                    if self.sessions[key].retry_count >= TIMEOUT_RETRIES:
                        log.debug("hit max retries on %s, giving up",
                                  self.sessions[key])
                        deletion_list.append(key)
                    else:
                        log.debug("resending on session %s", self.sessions[key])
                        self.sessions[key].state.resendLast()

            log.debug("Iterating deletion list.")
            for key in deletion_list:
                log.info('')
                log.info("Session %s complete" % key)
                if key in self.sessions:
                    log.debug("Gathering up metrics from session before deleting")
                    self.sessions[key].end()
                    metrics = self.sessions[key].metrics
                    if metrics.duration == 0:
                        log.info("Duration too short, rate undetermined")
                    else:
                        log.info("Transferred %d bytes in %.2f seconds"
                                 % (metrics.bytes, metrics.duration))
                        log.info("Average rate: %.2f kbps" % metrics.kbps)
                    log.info("%.2f bytes in resent data" % metrics.resent_bytes)
                    log.info("%d duplicate packets" % metrics.dupcount)
                    log.debug("Deleting session %s", key)
                    del self.sessions[key]
                    log.debug("Session list is now %s", self.sessions)
                else:
                    log.warn("Strange, session %s is not on the deletion list"
                             % key)

        self.is_running.clear()

        log.debug("server returning from while loop")
        self.shutdown_gracefully = self.shutdown_immediately = False

    def stop(self, now=False):
        if now:
            self.shutdown_immediately = True
        else:
            self.shutdown_gracefully = True


servidor = TftpServer()
servidor.listen(listenport=5432)