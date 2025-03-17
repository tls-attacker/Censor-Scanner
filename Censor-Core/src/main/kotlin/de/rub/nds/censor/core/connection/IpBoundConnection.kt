package de.rub.nds.censor.core.connection

import de.rub.nds.censor.core.network.IpAddress
import de.rub.nds.censor.core.util.PcapCapturer

abstract class IpBoundConnection<Manipulation>(val ip: IpAddress, timeout: Int, pcapCapturer: PcapCapturer? = null) :
    Connection<Manipulation>(timeout, pcapCapturer)