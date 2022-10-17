from IPv6Django.ipv6_task.ipv6_controller import IPv6Controller

ipv6_controller = IPv6Controller()


class Singleton:
    @staticmethod
    def get_ipv6_controller():
        return ipv6_controller
