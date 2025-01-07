"""Django API urlpatterns declaration for nautobot_device_lifecycle_mgmt app."""

from nautobot.apps.api import OrderedDefaultRouter

from nautobot_device_lifecycle_mgmt.api import views

router = OrderedDefaultRouter()
# add the name of your api endpoint, usually hyphenated model name in plural, e.g. "my-model-classes"
router.register("hardwarelcm", views.HardwareLCMViewSet)

urlpatterns = router.urls
