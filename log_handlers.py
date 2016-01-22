import boto3
from logging import Formatter
import botocore
from logging.handlers import SMTPHandler
import logging


class DebugHandler(logging.FileHandler):
    def emit(self, record):
        super(DebugHandler, self).emit(record)

    @staticmethod
    def get_handler(config):
        file_handler = DebugHandler(config.get_debug_log())
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(Formatter(
            '%(asctime)s %(levelname)s: %(message)s '
            '[in %(pathname)s:%(lineno)d]'
        ))
        return file_handler


class SESHandler(SMTPHandler):
    def emit(self, record):
        try:
            client = boto3.client('ses', region_name='us-east-1')
            client.send_email(
                Source=self.fromaddr,
                Destination={
                    'ToAddresses': self.toaddrs
                },
                Message={
                    'Subject': {
                        'Data': 'Production Error',
                        'Charset': 'iso-8859-1'
                    },
                    'Body': {
                        'Text': {
                            'Data': self.format(record),
                            'Charset': 'iso-8859-1'
                        }
                    }
                }
            )
        except botocore.exceptions.ClientError as e:
            print("Problem sending email %s " % e.response)

    @staticmethod
    def get_handler(config):
        mail_handler = SESHandler(mailhost='',
                                  fromaddr=config.get_sender_email(),
                                  toaddrs=config.get_recipient_emails(),
                                  subject='Production Error')
        mail_handler.setLevel(logging.ERROR)
        formatter = Formatter('''
            Name of the logger: %(name)s
            Logging level: %(levelname)s
            Pathname: %(pathname)s
            Filename portion of pathname: %(filename)s
            Module (name portion of filename): %(module)s
            Source line number: %(lineno)d
            Function name: %(funcName)s
            Time when the LogRecord was created: %(created)f
            Textual time: %(asctime)s
            Milliseconds: %(msecs)d
            Relative time: %(relativeCreated)d
            Thread ID: %(thread)d
            Thread name: %(threadName)s
            Process ID: %(process)d

            %(message)s
        ''')
        mail_handler.setFormatter(formatter)
        return mail_handler


def get_logger(config):
    logger = logging.getLogger()
    logger.setLevel(config.get_log_level())
    logger.addHandler(SESHandler.get_handler(config))
    logger.addHandler(DebugHandler.get_handler(config))
    return logger
