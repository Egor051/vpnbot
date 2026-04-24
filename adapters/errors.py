from __future__ import annotations


class AdapterError(RuntimeError):
    pass


class XrayConfigError(AdapterError):
    pass


class XrayInboundNotFoundError(XrayConfigError):
    pass


class XrayClientAlreadyExistsError(XrayConfigError):
    pass


class XrayApplyError(XrayConfigError):
    pass


class AwgConfigError(AdapterError):
    pass


class AwgPeerAlreadyExistsError(AwgConfigError):
    pass


class AwgApplyError(AwgConfigError):
    pass


class AwgIpAllocationError(AwgConfigError):
    pass
