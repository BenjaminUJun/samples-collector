import web
from pymongo import MongoClient

urls=(
    '/samples','list_samples',
    '/samples/(.*)','get_samples'
)

app = web.application(urls,globals())
client= MongoClient('localhost', 27017)
samples = client.samples

class list_samples:
    def GET(self):
        output = samples.sampleinfo.find()
        return output

class get_samples:
    def GET(self,ip_src):
    	output = samples.sampleinfo.find({"ip_src":ip_src})
        return output

if __name__ == '__main__':
    app.run()  