package com.openworld.app.service

import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import com.openworld.core.OpenWorldCore

class VpnTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        updateTile()
    }

    override fun onClick() {
        super.onClick()
        val wasRunning = OpenWorldCore.isRunning()
        if (wasRunning) {
            OpenWorldVpnService.stop(this)
        } else {
            OpenWorldVpnService.start(this)
        }
        // 乐观更新：立即反转状态
        qsTile?.let {
            it.state = if (wasRunning) Tile.STATE_INACTIVE else Tile.STATE_ACTIVE
            it.updateTile()
        }
    }

    private fun updateTile() {
        qsTile?.let {
            it.state = if (OpenWorldCore.isRunning()) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
            it.label = "OpenWorld"
            it.updateTile()
        }
    }
}
