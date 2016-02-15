from fodtlmon_middleware.sysmon import *
from django.contrib.auth.models import User


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
    def eval(self, valuation=None):
        args2 = super().eval(valuation=valuation)
        try:
            u1 = User.objects.filter(id=args2[0].name).first()
            u2 = User.objects.filter(username=args2[1].name).first()
            return u1 == u2
        except:
            return False


class ReqIn(IPredicate):  # TODO : add to standard lib
    """ Request regexp """
    def eval(self, valuation=None):
        args2 = super().eval(valuation=valuation)
        return args2[0].name[1:-1] in args2[1].name

################################
# HTTP rules
################################
Sysmon.add_http_rule("UserProfile",
                     "G( ![id:UIDL uname:USER req:GET]( ReqIn(r\"taskManager/profile/\", req) => UserEq(id, uname)) )",
                     description="", control_type=Monitor.MonControlType.REAL_TIME)
