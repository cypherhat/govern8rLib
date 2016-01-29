import notary_client
notary_obj=notary_client.Notary("notaryconfig.ini")
notary_obj.create_wallet("notaryconfig.ini")
notary_obj.load_wallet("test123")
result = notary_obj.register_user("test123")