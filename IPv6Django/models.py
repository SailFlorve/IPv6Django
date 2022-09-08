from django.db import models
from rest_framework import serializers


class IPv6TaskModel(models.Model):
    TYPE_GENERATE = 0
    TYPE_VULN_SCAN = 1
    TYPE_ALL = 2

    TYPE_GET_STATE = 0
    TYPE_GET_RESULT = 1
    TYPE_GET_ALL = 2
    TYPE_PARSE_RESULT = 3
    TYPE_GET_UPLOAD = 4
    TYPE_GET_LOG = 5

    TYPE_TERMINATE = 0
    TYPE_DELETE = 1

    TYPE_QUERY_LIST = 0
    TYPE_STATISTICS = 1

    STATE_ERROR = 0
    STATE_PREPROCESS = 1
    STATE_GENERATE_IPV6 = 2
    STATE_VULN_SCAN = 3
    STATE_FINISH = 4

    task_id = models.CharField(max_length=100, primary_key=True)
    task_name = models.CharField(max_length=100)
    task_type = models.IntegerField(default=0)
    state = models.IntegerField(default=0)

    created_time = models.DateTimeField(auto_now_add=True)
    update_time = models.DateTimeField(auto_now=True)

    upload_path = models.CharField(max_length=300)
    result_path = models.CharField(max_length=300, default="")

    params = models.TextField(default="")
    result = models.TextField(default="")

    def __str__(self):
        return self.task_id

    class Meta:
        db_table = "tb_ipv6_task"
        ordering = ["-created_time"]

    @staticmethod
    def get_model_by_task_id(task_id):
        try:
            model = IPv6TaskModel.objects.get(task_id=task_id)
            return model
        except IPv6TaskModel.DoesNotExist:
            return None

    @staticmethod
    def update_result(task_id, result: str):
        try:
            model = IPv6TaskModel.get_model_by_task_id(task_id)
            model.result = result
            model.save()
        except Exception:
            pass

    @staticmethod
    def update_state(task_id, state: int):
        try:
            model = IPv6TaskModel.get_model_by_task_id(task_id)
            model.state = state
            model.save()
        except Exception:
            pass


class IPv6TaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = IPv6TaskModel
        fields = '__all__'


if __name__ == '__main__':
    pass
