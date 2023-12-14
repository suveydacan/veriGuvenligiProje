from pymongo import MongoClient



def get_db_handle(db_name, host, port, username, password):

    client = MongoClient(host=host,
                        port=int(port)
                        )
    db_handle = client['testdb']
    return db_handle, client




get_db_handle('testdb', 'localhost', 27017, 'username', 'password')