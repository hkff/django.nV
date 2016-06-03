from accmon.sysmon import *
from django.contrib.auth.models import User
from accmon.plugins import remote, arduino, assertionToolkit


################################
# Register actors
################################
Sysmon.register_actor("alice", "https://alice-hkff.c9users.io", 8080)


################################
# Custom attributes to log
################################
def user_id_log(request, view, args, kwargs, response):
    if "taskManager/profile/" in request.path and request.method == "GET":
        return P("UIDL", args=[Constant(request.path.split("/")[-1])])

Sysmon.add_log_attribute(LogAttribute("Profile_User_id", enabled=True,
            description="The scheme of the request (http or https usually).",
            eval_fx=user_id_log), target=Monitor.MonType.HTTP)


################################
# Custom predicates/functions
################################
class UserEq(IPredicate):
    """ Compare user by id """
    def eval(self, valuation=None, trace=None):
        args2 = super().eval(valuation=valuation, trace=trace)
        try:
            u1 = User.objects.filter(id=args2[0].name).first()
            u2 = User.objects.filter(username=args2[1].name).first()
            return u1 == u2
        except:
            return False


class ReqIn(IPredicate):
    """ Request regexp """
    def eval(self, valuation=None, trace=None):
        args2 = super().eval(valuation=valuation, trace=trace)
        return args2[0].name[1:-1] in args2[1].name


################################
# Monitors
################################
Sysmon.add_http_rule("UserProfile",
                     "G( ![id:UIDL uname:USER req:GET]( ReqIn(r\"taskManager/profile/\", req) => UserEq(id, uname)) )",
                     description="", control_type=Monitor.MonControlType.REAL_TIME)

Sysmon.add_http_rule("Alice",
                     "@alice(G( ~ADMIN('root')) )",
                     description="", control_type=Monitor.MonControlType.POSTERIORI)

remote.Remote.add_rule("cdroot", "G( ![path:cd]( ~Regex(path, r\"/root/*\")) )")

arduino.Arduino.add_rule("light", "G( ![x:LIGHT]( Lt(x, '10') ))", violation_formula="F(STOP(0))")

assertionToolkit.AssertionToolkit.add_rule("Intrusion_Detection", "G( ![x:APPLE_Id]( APPLE_Id(x) => F(AAS_Id(x)) ) )", liveness=5)
