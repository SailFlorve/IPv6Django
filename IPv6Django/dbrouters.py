from IPv6Django.models import IPv6TaskModel, VulnScriptModel


class MyDBRouter(object):

    def db_for_read(self, model, **hints):
        if model == IPv6TaskModel:
            return 'default'
        if model == VulnScriptModel:
            return 'vuln'

    def db_for_write(self, model, **hints):
        if model == IPv6TaskModel:
            return 'default'
        if model == VulnScriptModel:
            return 'vuln'
