from datadog_checks.base import AgentCheck
from datadog_checks.base.utils.time import get_timestamp


class HelloCheck(AgentCheck):
    def check(self, instance):
        data = {}
        data['timestamp'] = get_timestamp()
        data['message'] = "second log message"
        data['ddtags'] = "env:dev,log:second"

        self.send_log(data)
