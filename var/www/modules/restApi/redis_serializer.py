# coding: utf-8
"""
Elastic Search json converter
"""

##################################
# Import External packages
##################################
import json

##################################
# Import Project packages
##################################


class RedissearchResult():
    """
    Redissearch Result object
    """
    def __init__(self, docs, total, *args, **kwargs):
        self.docs = [ComboLeak(**x) for x in docs]
        self.total = total


class ComboLeak():
    """
    ComboLeak plain object
    """

    def __init__(self, cid, payload, email, *args, **kwargs):
        self.id = cid
        self.payload = payload
        self.email = email

    def json_encode(self):
        """
        Return the JSON string representation of the ComboLeak
        """
        return json.dumps({
            "id": f"{self.id}",
            "email": f"{self.email}"
        })


class JsonSerializer:
    """
    Serialize an object
    """
    def __init__(self):
        self._json_object = None

    def start_object(self, object_id):
        """
        Define first JSON property
        """
        self._json_object = {
            'id': object_id
        }

    def start_no_object(self):
        """
        Define first JSON property
        """
        self._json_object = {}

    def add_property(self, name, value):
        """
        Add property dynamicaly
        """
        self._json_object[name] = value

    def to_str(self):
        """
        Return a JSON formatted string of the object
        """
        return json.dumps(self._json_object)


class ComboLeakSerializer(RedissearchResult):
    """
    Serialize a ComboLeak recorded in Redisearch
    """
    def __init__(self, docs, total, *args, **kwargs):
        super(ComboLeakSerializer, self).__init__(docs, total, *args, **kwargs)
        self.serial = [self.to_json(x) for x in self.docs]


    def to_json(self, doc):
        """
        Build JSON representation of the Demand
        """
        serializer = JsonSerializer()
        serializer.start_object(doc.id)
        serializer.add_property("email", doc.email)

        return serializer._json_object


# TODO add test in unit test folder
if __name__ == '__main__':
    es_data1 = '{ \
            "total": 2, \
            "duration": 27.327775955200195, \
            "docs": [ \
                { \
                    "id": "comboleak:record:3bb915e62acc716c149c4c5179b56755e61d783a197dc00ad7378fb9544cc5b0", \
                    "cid": "3bb915e62acc716c149c4c5179b56755e61d783a197dc00ad7378fb9544cc5b0", \
                    "payload": null, \
                    "email": "jacques.eloidin@orange.mq" \
                }, \
                { \
                    "id": "comboleak:record:76f453c8adb4829d15ea74076e28ebb691c157eb9daffb127a59139ab45675d9", \
                    "cid": "76f453c8adb4829d15ea74076e28ebb691c157eb9daffb127a59139ab45675d9", \
                    "payload": null, \
                    "email": "ashaukh@orange.mu" \
                } \
            ] \
        }'

    j = json.loads(es_data1)
    es = ComboLeakSerializer(**j)
    print(json.dumps(es.serial))
