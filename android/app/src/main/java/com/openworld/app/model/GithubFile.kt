package com.openworld.app.model

import com.google.gson.annotations.SerializedName

data class GithubFile(
    @SerializedName("name") val name: String,
    @SerializedName("path") val path: String,
    @SerializedName("size") val size: Long,
    @SerializedName("download_url") val download_url: String?
)

data class GithubTreeResponse(
    @SerializedName("tree") val tree: List<GithubTreeItem>
)

data class GithubTreeItem(
    @SerializedName("path") val path: String,
    @SerializedName("type") val type: String
)







