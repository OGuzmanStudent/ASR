import types
from tftpy.TftpShared import *
import time
from tftpy.TftpPacketTypes import *
from tftpy.TftpContexts import TftpContextClientDownload, TftpContextClientUpload


class TftpClient(TftpSession):
    def __init__(self, host, port, options={}):
        TftpSession.__init__(self)
        self.context = None
        self.host = host
        self.iport = port
        self.filename = None
        self.options = options
        if 'blksize' in self.options:
            size = self.options['blksize']
            tftpassert(types.IntType == type(size), "blksize must be an int")
            if size < MIN_BLKSIZE or size > MAX_BLKSIZE:
                raise TftpException("Invalid blksize: %d" % size)

    def download(self, filename, output, packethook=None, timeout=SOCK_TIMEOUT):
        log.debug("Creating download context with the following params:")
        log.debug("host = %s, port = %s, filename = %s, output = %s",
                  self.host, self.iport, filename, output)
        log.debug("options = %s, packethook = %s, timeout = %s",
                  self.options, packethook, timeout)
        self.context = TftpContextClientDownload(self.host,
                                                 self.iport,
                                                 filename,
                                                 output,
                                                 self.options,
                                                 packethook,
                                                 timeout)
        self.context.start()
        # Download happens here
        self.context.end()

        metrics = self.context.metrics

        log.info('')
        log.info("Download complete.")
        if metrics.duration == 0:
            log.info("Duration too short, rate undetermined")
        else:
            log.info("Downloaded %.2f bytes in %.2f seconds" % (metrics.bytes, metrics.duration))
            log.info("Average rate: %.2f kbps" % metrics.kbps)
        log.info("%.2f bytes in resent data" % metrics.resent_bytes)
        log.info("Received %d duplicate packets" % metrics.dupcount)

    def upload(self, filename, input, packethook=None, timeout=SOCK_TIMEOUT):
        self.context = TftpContextClientUpload(self.host,
                                               self.iport,
                                               filename,
                                               input,
                                               self.options,
                                               packethook,
                                               timeout)
        self.context.start()
        # Upload happens here
        self.context.end()

        metrics = self.context.metrics

        log.info('')
        log.info("carga completa")
        if metrics.duration == 0:
            log.info("No se puede estimar un rango")
        else:
            log.info("Se cargaron %d bytes en %.2f segundos" % (metrics.bytes, metrics.duration))
            log.info("Velocidad promedio: %.2f kbps" % metrics.kbps)
        log.info("%.2f bytes se reenviaron" % metrics.resent_bytes)
        log.info("Reenviados: %d paquetes" % metrics.dupcount)


try:
    ip = input("Ingresa la ip del servidor:")
    print("\n")
    puerto = input("Ingresa el puerto del servidor:")

    while True:
        menu = input(
            "Que deseas hacer?\n 0)Descargar un archivo\n 1)Enviar un archivo\n 2)Cambiar la ip y puerto\n 3)Salir\n")

        if menu == "0":
            origen = input("Ingresa el nombre del archivo a descargar: ")
            destino = "./descargas/" + time.strftime("%H_%M_S") + origen
            client = TftpClient(ip, int(puerto))
            client.download(origen, destino)
            print("Se descargo" + destino)
        elif menu == "1":
            origen = input("Ingresa el nombre del archivo a cargar: ")
            client = TftpClient(ip, int(puerto))
            client.upload("./subido/" + origen.split("/")[-1], origen)
        elif menu == "2":
            puerto = input("Ingresa el puerto del servidor: ")
            ip = input("Ingresa la ip del servidor: ")

        elif menu == "3":
            break
        else:
            print("Ingresa un numero de opcion valida")
except Exception as e:
    print(e)
    print("ocurrio un error")