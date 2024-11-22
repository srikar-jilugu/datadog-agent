from datadog_checks.base import AgentCheck
from datadog_checks.base.utils.time import get_timestamp


class HelloCheck(AgentCheck):
    def check(self, instance):
        data = {}
        data['timestamp'] = get_timestamp()
        data['message'] = "first log message"
        data['ddtags'] = "env:dev,log:first"

        self.send_log(data)
