import notary_client
import wallet
import configuration
import log_handlers

config = configuration.NotaryConfiguration("notaryconfig.ini")
ssl_verify_mode = config.get_ssl_verify_mode()
logger = log_handlers.get_logger(config)
logger.debug("-------------------------ENVIRONMENT--------------------------")
logger.debug("Am I Local: %s " % config.is_local_host())
wallet.create_wallet("ClientWallet", "test123", logger)
wallet.load_wallet("ClientWallet", "test123", logger)

notary_obj=notary_client.Notary("notaryconfig.ini")
notary_obj.create_wallet("test123")
notary_obj.load_wallet("test123")
result = notary_obj.register_user("test123")