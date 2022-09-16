from rest_framework.response import Response
from rest_framework.serializers import Serializer

from IPv6Django.bean.beans import Status, PageInfo, BaseBean


class CustomResponse(Response):
    def __init__(self, code=Status.OK, msg: str | dict = 'success',
                 data=None, page_info: PageInfo = None, status=None, template_name=None, headers=None,
                 exception=False, content_type=None, **kwargs):
        super().__init__(None, status=status)

        if isinstance(data, Serializer):
            msg = (
                'You passed a Serializer instance as data, but '
                'probably meant to pass serialized `.data` or '
                '`.error`. representation.'
            )
            raise AssertionError(msg)

        if isinstance(msg, dict):
            for k, v in msg.items():
                for i in v:
                    msg = "%s:%s" % (k, i)

        if isinstance(data, BaseBean):
            data = data.to_dict()

        self.data = {'status': code, 'msg': msg, 'data': data}
        if page_info is not None:
            self.data['page_info'] = page_info.to_dict()

        self.data.update(kwargs)
        self.template_name = template_name
        self.exception = exception
        self.content_type = content_type

        if headers:
            for name, value in headers.items():
                self[name] = value
