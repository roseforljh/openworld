package com.openworld.app.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.RadioButtonChecked
import androidx.compose.material.icons.rounded.RadioButtonUnchecked
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import com.openworld.app.R
import com.openworld.app.ui.theme.Destructive
import com.openworld.app.ui.theme.Neutral500
import androidx.compose.foundation.interaction.MutableInteractionSource
import com.openworld.app.model.NodeFilter
import com.openworld.app.model.FilterMode
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.border
import androidx.compose.foundation.Image
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.animation.*
import androidx.compose.animation.core.tween
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.ExpandLess
import androidx.compose.material.icons.rounded.ExpandMore
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material3.IconButton
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Divider
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.graphics.asImageBitmap
import androidx.core.graphics.drawable.toBitmap
import androidx.compose.foundation.text.ClickableText
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.style.TextDecoration
import android.content.Intent
import android.net.Uri
import com.openworld.app.model.InstalledApp
import com.openworld.app.repository.InstalledAppsRepository
import com.openworld.app.model.ProfileUi
import com.openworld.app.model.NodeUi
import kotlinx.coroutines.launch
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.ui.draw.scale



@Composable
fun ConfirmDialog(
    title: String,
    message: String,
    confirmText: String = stringResource(R.string.common_confirm),
    isDestructive: Boolean = false,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit
) {
    Dialog(onDismissRequest = onDismiss) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(MaterialTheme.colorScheme.surface, RoundedCornerShape(28.dp))
                .padding(24.dp)
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface
            )
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                text = message,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(24.dp))

            Button(
                onClick = onConfirm,
                modifier = Modifier.fillMaxWidth().height(50.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (isDestructive) Destructive else MaterialTheme.colorScheme.primary,
                    contentColor = if (isDestructive) Color.White else MaterialTheme.colorScheme.onPrimary
                ),
                shape = RoundedCornerShape(25.dp)
            ) {
                Text(
                    text = confirmText,
                    fontWeight = FontWeight.Bold,
                    color = if (isDestructive) Color.White else MaterialTheme.colorScheme.onPrimary
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            TextButton(
                onClick = onDismiss,
                modifier = Modifier.fillMaxWidth().height(50.dp),
                colors = ButtonDefaults.textButtonColors(contentColor = Neutral500)
            ) {
                Text(stringResource(R.string.common_cancel))
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun InputDialog(
    title: String,
    initialValue: String = "",
    placeholder: String = "",
    confirmText: String = stringResource(R.string.common_confirm),
    singleLine: Boolean = true,
    minLines: Int = 1,
    maxLines: Int = if (singleLine) 1 else 6,
    onConfirm: (String) -> Unit,
    onDismiss: () -> Unit
) {
    var text by remember { mutableStateOf(initialValue) }
    val interactionSource = remember { MutableInteractionSource() }
    val scrollState = rememberScrollState()

    Dialog(onDismissRequest = onDismiss) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(MaterialTheme.colorScheme.surface, RoundedCornerShape(28.dp))
                .padding(24.dp)
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface
            )
            Spacer(modifier = Modifier.height(16.dp))

            BasicTextField(
                value = text,
                onValueChange = { text = it },
                modifier = Modifier
                    .fillMaxWidth()
                    .then(if (singleLine) Modifier.horizontalScroll(scrollState) else Modifier),
                singleLine = singleLine,
                minLines = minLines,
                maxLines = maxLines,
                textStyle = MaterialTheme.typography.bodyLarge.copy(
                    color = MaterialTheme.colorScheme.onSurface
                ),
                cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
                interactionSource = interactionSource,
                decorationBox = { innerTextField ->
                    OutlinedTextFieldDefaults.DecorationBox(
                        value = text,
                        innerTextField = innerTextField,
                        enabled = true,
                        singleLine = singleLine,
                        visualTransformation = VisualTransformation.None,
                        interactionSource = interactionSource,
                        placeholder = {
                            Text(
                                text = placeholder,
                                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
                            )
                        },
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedTextColor = MaterialTheme.colorScheme.onSurface,
                            unfocusedTextColor = MaterialTheme.colorScheme.onSurface,
                            focusedBorderColor = MaterialTheme.colorScheme.primary,
                            unfocusedBorderColor = MaterialTheme.colorScheme.outline,
                            focusedLabelColor = MaterialTheme.colorScheme.primary,
                            unfocusedLabelColor = MaterialTheme.colorScheme.onSurfaceVariant
                        ),
                        container = {
                            OutlinedTextFieldDefaults.Container(
                                enabled = true,
                                isError = false,
                                interactionSource = interactionSource,
                                colors = OutlinedTextFieldDefaults.colors(
                                    focusedBorderColor = MaterialTheme.colorScheme.primary,
                                    unfocusedBorderColor = MaterialTheme.colorScheme.outline
                                ),
                                shape = RoundedCornerShape(16.dp)
                            )
                        }
                    )
                }
            )

            Spacer(modifier = Modifier.height(24.dp))

            Button(
                onClick = { onConfirm(text) },
                modifier = Modifier.fillMaxWidth().height(50.dp),
                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary, contentColor = MaterialTheme.colorScheme.onPrimary),
                shape = RoundedCornerShape(25.dp)
            ) {
                Text(
                    text = confirmText,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onPrimary
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            TextButton(
                onClick = onDismiss,
                modifier = Modifier.fillMaxWidth().height(50.dp),
                colors = ButtonDefaults.textButtonColors(contentColor = Neutral500)
            ) {
                Text(stringResource(R.string.common_cancel))
            }
        }
    }
}

@Composable
fun SingleSelectDialog(
    title: String,
    options: List<String>,
    selectedIndex: Int,
    optionsHeight: androidx.compose.ui.unit.Dp? = null,
    onSelect: (Int) -> Unit,
    onDismiss: () -> Unit
) {
    var tempSelectedIndex by remember(selectedIndex) { mutableStateOf(selectedIndex) }

    Dialog(onDismissRequest = onDismiss) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(MaterialTheme.colorScheme.surface, RoundedCornerShape(28.dp))
                .padding(24.dp)
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface
            )
            Spacer(modifier = Modifier.height(16.dp))

            Column(
                modifier = Modifier
                    .then(
                        if (optionsHeight != null) {
                            Modifier.height(optionsHeight)
                        } else {
                            Modifier.weight(weight = 1f, fill = false)
                        }
                    )
                    .verticalScroll(rememberScrollState())
            ) {
                options.forEachIndexed { index, option ->
                    val isSelected = index == tempSelectedIndex
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(12.dp))
                            .background(if (isSelected) MaterialTheme.colorScheme.primary.copy(alpha = 0.1f) else Color.Transparent)
                            .clickable { tempSelectedIndex = index }
                            .padding(vertical = 12.dp, horizontal = 8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = if (isSelected) Icons.Rounded.RadioButtonChecked else Icons.Rounded.RadioButtonUnchecked,
                            contentDescription = null,
                            tint = if (isSelected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(16.dp))
                        Text(
                            text = option,
                            style = MaterialTheme.typography.bodyLarge,
                            color = if (isSelected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            Button(
                onClick = { onSelect(tempSelectedIndex) },
                modifier = Modifier.fillMaxWidth().height(50.dp),
                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary, contentColor = MaterialTheme.colorScheme.onPrimary),
                shape = RoundedCornerShape(25.dp)
            ) {
                Text(
                    text = stringResource(R.string.common_ok),
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onPrimary
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            TextButton(
                onClick = onDismiss,
                modifier = Modifier.fillMaxWidth().height(50.dp),
                colors = ButtonDefaults.textButtonColors(contentColor = Neutral500)
            ) {
                Text(stringResource(R.string.common_cancel))
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NodeFilterDialog(
    currentFilter: NodeFilter,
    onConfirm: (NodeFilter) -> Unit,
    onDismiss: () -> Unit
) {
    var filterMode by remember { mutableStateOf(currentFilter.filterMode) }
    var includeText by remember {
        mutableStateOf(currentFilter.effectiveIncludeKeywords.joinToString(", "))
    }
    var excludeText by remember {
        mutableStateOf(currentFilter.effectiveExcludeKeywords.joinToString(", "))
    }

    Dialog(onDismissRequest = onDismiss) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(MaterialTheme.colorScheme.surface, RoundedCornerShape(28.dp))
                .padding(24.dp)
        ) {
            Text(
                text = stringResource(R.string.node_filter_title),
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface
            )
            Spacer(modifier = Modifier.height(16.dp))

            Text(
                text = stringResource(R.string.node_filter_mode),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(8.dp))

            val modes = listOf(
                FilterMode.NONE to stringResource(R.string.node_filter_none),
                FilterMode.INCLUDE to stringResource(R.string.node_filter_include),
                FilterMode.EXCLUDE to stringResource(R.string.node_filter_exclude)
            )
            modes.forEach { (mode, label) ->
                val isSelected = filterMode == mode
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(
                            if (isSelected) MaterialTheme.colorScheme.primary.copy(alpha = 0.1f)
                            else Color.Transparent
                        )
                        .clickable { filterMode = mode }
                        .padding(vertical = 10.dp, horizontal = 8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = if (isSelected) Icons.Rounded.RadioButtonChecked
                        else Icons.Rounded.RadioButtonUnchecked,
                        contentDescription = null,
                        tint = if (isSelected) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(24.dp)
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Text(
                        text = label,
                        style = MaterialTheme.typography.bodyLarge,
                        color = if (isSelected) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.onSurface
                    )
                }
            }

            if (filterMode != FilterMode.NONE) {
                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    text = stringResource(R.string.node_filter_keywords),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(8.dp))

                val keywordsText = if (filterMode == FilterMode.INCLUDE) includeText else excludeText
                val filterInteractionSource = remember { MutableInteractionSource() }

                BasicTextField(
                    value = keywordsText,
                    onValueChange = {
                        if (filterMode == FilterMode.INCLUDE) includeText = it
                        else excludeText = it
                    },
                    modifier = Modifier.fillMaxWidth(),
                    textStyle = MaterialTheme.typography.bodyLarge.copy(
                        color = MaterialTheme.colorScheme.onSurface
                    ),
                    cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
                    interactionSource = filterInteractionSource,
                    decorationBox = { innerTextField ->
                        OutlinedTextFieldDefaults.DecorationBox(
                            value = keywordsText,
                            innerTextField = innerTextField,
                            enabled = true,
                            singleLine = false,
                            visualTransformation = VisualTransformation.None,
                            interactionSource = filterInteractionSource,
                            placeholder = {
                                Text(
                                    text = stringResource(R.string.node_filter_keywords_hint),
                                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
                                )
                            },
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = MaterialTheme.colorScheme.primary,
                                unfocusedBorderColor = MaterialTheme.colorScheme.outline
                            ),
                            container = {
                                OutlinedTextFieldDefaults.Container(
                                    enabled = true,
                                    isError = false,
                                    interactionSource = filterInteractionSource,
                                    colors = OutlinedTextFieldDefaults.colors(
                                        focusedBorderColor = MaterialTheme.colorScheme.primary,
                                        unfocusedBorderColor = MaterialTheme.colorScheme.outline
                                    ),
                                    shape = RoundedCornerShape(16.dp)
                                )
                            }
                        )
                    }
                )

                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = stringResource(R.string.node_filter_keywords_tip),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
                )
            }

            Spacer(modifier = Modifier.height(24.dp))

            Button(
                onClick = {
                    val parseKeywords = { text: String ->
                        text.split(",").map { it.trim() }.filter { it.isNotEmpty() }
                    }
                    onConfirm(
                        NodeFilter(
                            filterMode = filterMode,
                            includeKeywords = if (filterMode == FilterMode.INCLUDE) parseKeywords(includeText) else emptyList(),
                            excludeKeywords = if (filterMode == FilterMode.EXCLUDE) parseKeywords(excludeText) else emptyList()
                        )
                    )
                },
                modifier = Modifier.fillMaxWidth().height(50.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.primary,
                    contentColor = MaterialTheme.colorScheme.onPrimary
                ),
                shape = RoundedCornerShape(25.dp)
            ) {
                Text(
                    text = stringResource(R.string.common_confirm),
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onPrimary
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            TextButton(
                onClick = onDismiss,
                modifier = Modifier.fillMaxWidth().height(50.dp),
                colors = ButtonDefaults.textButtonColors(contentColor = Neutral500)
            ) {
                Text(stringResource(R.string.common_cancel))
            }
        }
    }
}

@Composable
fun AppMultiSelectDialog(
    initialSelectedPackageNames: Set<String>,
    onConfirm: (Set<String>) -> Unit,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val repository = remember { InstalledAppsRepository.getInstance(context) } // Assume getInstance exists
    
    // State
    var allApps by remember { mutableStateOf<List<InstalledApp>>(emptyList()) }
    var isLoading by remember { mutableStateOf(true) }
    var searchQuery by remember { mutableStateOf("") }
    var showSystemApps by remember { mutableStateOf(false) }
    var showNoLauncherApps by remember { mutableStateOf(false) } // Default false
    // Selected apps
    var selectedApps by remember { mutableStateOf(initialSelectedPackageNames) }

    // Load apps
    LaunchedEffect(showSystemApps, showNoLauncherApps) {
        isLoading = true
        scope.launch {
            repository.loadApps()
            val apps = repository.installedApps.value
            allApps = if (showSystemApps) apps else apps.filter { !it.isSystemApp }
            isLoading = false
        }
    }

    // Filtered apps
    val filteredApps by remember {
        derivedStateOf {
            if (searchQuery.isEmpty()) {
                allApps
            } else {
                allApps.filter {
                    it.appName.contains(searchQuery, ignoreCase = true) ||
                            it.packageName.contains(searchQuery, ignoreCase = true)
                }
            }
        }
    }
    
    // Select All logic (for filtered list)
    val isAllFilteredSelected by remember {
       derivedStateOf {
           filteredApps.isNotEmpty() && filteredApps.all { it.packageName in selectedApps }
       }
    }


    Dialog(onDismissRequest = onDismiss) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .fillMaxHeight(0.85f)
                .background(MaterialTheme.colorScheme.surface, RoundedCornerShape(28.dp))
                .padding(24.dp)
        ) {
            // Header
            Text(
                text = stringResource(R.string.common_select_title, stringResource(R.string.app_list_quick_select)), // Reusing "Common" or specific
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface
            )
            
            Spacer(modifier = Modifier.height(16.dp))

            // Search
            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                placeholder = { Text(stringResource(R.string.app_list_search_hint)) },
                leadingIcon = { Icon(Icons.Rounded.ExpandMore, contentDescription = null, modifier = Modifier.size(20.dp)) }, // Should be Search icon, but using ExpandMore as placeholder if Search not imported
                trailingIcon = {
                     if (searchQuery.isNotEmpty()) {
                         IconButton(onClick = { searchQuery = "" }) {
                             Icon(Icons.Rounded.Refresh, contentDescription = "Clear") // Should be Close/Clear
                         }
                     }
                },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                shape = RoundedCornerShape(16.dp)
            )
             
            Spacer(modifier = Modifier.height(8.dp))
            
            // Filters (System / No Launcher)
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                 FilterChip(
                     selected = showSystemApps,
                     onClick = { showSystemApps = !showSystemApps },
                     label = stringResource(R.string.app_list_show_system)
                 )
                 FilterChip(
                     selected = showNoLauncherApps,
                     onClick = { showNoLauncherApps = !showNoLauncherApps },
                     label = stringResource(R.string.app_list_show_no_launcher)
                 )
            }
            
            Spacer(modifier = Modifier.height(8.dp))

            // Select All / Count
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                     text = stringResource(R.string.app_list_loaded, filteredApps.size, allApps.size),
                     style = MaterialTheme.typography.bodySmall,
                     color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                
                TextButton(onClick = {
                    if (isAllFilteredSelected) {
                        // Deselect all filtered
                        val newSelection = selectedApps.toMutableSet()
                        filteredApps.forEach { newSelection.remove(it.packageName) }
                        selectedApps = newSelection
                    } else {
                        // Select all filtered
                        val newSelection = selectedApps.toMutableSet()
                        filteredApps.forEach { newSelection.add(it.packageName) }
                        selectedApps = newSelection
                    }
                }) {
                     Text(if (isAllFilteredSelected) stringResource(R.string.common_clear) else stringResource(R.string.common_select_all))
                }
            }
            
            Divider(color = MaterialTheme.colorScheme.outlineVariant)

            // App List
            if (isLoading) {
                Box(modifier = Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator()
                }
            } else {
                LazyColumn(
                    modifier = Modifier.weight(1f).fillMaxWidth()
                ) {
                    items(filteredApps, key = { it.packageName }) { app ->
                        AppItem(
                            app = app,
                            isSelected = app.packageName in selectedApps,
                            onToggle = {
                                val newSelection = selectedApps.toMutableSet()
                                if (newSelection.contains(app.packageName)) {
                                    newSelection.remove(app.packageName)
                                } else {
                                    newSelection.add(app.packageName)
                                }
                                selectedApps = newSelection
                            }
                        )
                    }
                }
            }
            
            Spacer(modifier = Modifier.height(16.dp))
            
            // Buttons
             Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                TextButton(
                    onClick = onDismiss,
                    modifier = Modifier.weight(1f).height(50.dp),
                    colors = ButtonDefaults.textButtonColors(contentColor = Neutral500)
                ) {
                    Text(stringResource(R.string.common_cancel))
                }

                Button(
                    onClick = { onConfirm(selectedApps) },
                    modifier = Modifier.weight(1f).height(50.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.primary,
                        contentColor = MaterialTheme.colorScheme.onPrimary
                    ),
                    shape = RoundedCornerShape(25.dp)
                ) {
                    Text(
                        stringResource(R.string.common_confirm),
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        }
    }
}

@Composable
fun FilterChip(selected: Boolean, onClick: () -> Unit, label: String) {
    val backgroundColor = if (selected) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant
    val contentColor = if (selected) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSurfaceVariant
    
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(8.dp))
            .background(backgroundColor)
            .clickable(onClick = onClick)
            .padding(horizontal = 12.dp, vertical = 6.dp)
    ) {
        Text(text = label, style = MaterialTheme.typography.labelMedium, color = contentColor)
    }
}

@Composable
fun AppItem(app: InstalledApp, isSelected: Boolean, onToggle: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onToggle)
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        // Icon (Placeholder if no icon loader)
        // Ideally use Coil or a custom ImageLoader. For now just a box or simple icon
        Box(
             modifier = Modifier.size(40.dp).background(Color.Gray, RoundedCornerShape(8.dp)),
             contentAlignment = Alignment.Center
        ) {
              Text(app.appName.take(1), color = Color.White)
        }
        
        Spacer(modifier = Modifier.width(12.dp))
        
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = app.appName,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Medium,
                color = MaterialTheme.colorScheme.onSurface
            )
            Text(
                text = app.packageName,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        
        Checkbox(
            checked = isSelected,
            onCheckedChange = { onToggle() }
        )
    }
}

@Composable
fun ProfileNodeSelectDialog(
    title: String,
    profiles: List<ProfileUi>,
    nodesForSelection: List<NodeUi>,
    selectedNodeRef: String?,
    onSelect: (String) -> Unit,
    onDismiss: () -> Unit
) {
    fun toNodeRef(node: NodeUi): String = "${node.sourceProfileId}::${node.name}"

    val nodesByProfile = remember(nodesForSelection) {
        nodesForSelection.groupBy { it.sourceProfileId }
    }
    val profileOrder = remember(profiles) { profiles.sortedBy { it.name } }
    val knownProfileIds = remember(profiles) { profiles.map { it.id }.toSet() }

    var expandedProfileId by remember { mutableStateOf<String?>(null) }

    Dialog(onDismissRequest = onDismiss) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(MaterialTheme.colorScheme.surface, RoundedCornerShape(28.dp))
                .padding(24.dp)
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface
            )

            Spacer(modifier = Modifier.height(16.dp))

            LazyColumn(
                modifier = Modifier
                    .fillMaxWidth()
                    .fillMaxHeight(0.72f)
            ) {
                profileOrder.forEach { profile ->
                    val itemsForProfile = nodesByProfile[profile.id].orEmpty()
                    val isExpanded = expandedProfileId == profile.id
                    val enabled = itemsForProfile.isNotEmpty()

                    item(key = "profile_${profile.id}") {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(12.dp))
                                .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f))
                                .animateContentSize(animationSpec = tween(durationMillis = 220))
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable(enabled = enabled) {
                                        expandedProfileId = if (isExpanded) null else profile.id
                                    }
                                    .padding(vertical = 12.dp, horizontal = 12.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = profile.name,
                                        style = MaterialTheme.typography.bodyLarge,
                                        color = if (enabled) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
                                        fontWeight = FontWeight.Medium
                                    )
                                    Text(
                                        text = stringResource(R.string.rulesets_nodes_count, itemsForProfile.size),
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                                Icon(
                                    imageVector = if (isExpanded) Icons.Rounded.ExpandLess else Icons.Rounded.ExpandMore,
                                    contentDescription = null,
                                    tint = if (enabled) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
                                )
                            }

                            AnimatedVisibility(
                                visible = isExpanded,
                                enter = fadeIn(animationSpec = tween(180)),
                                exit = fadeOut(animationSpec = tween(120))
                            ) {
                                LazyColumn(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .heightIn(max = 260.dp)
                                ) {
                                    items(itemsForProfile, key = { it.id }) { node ->
                                        val ref = toNodeRef(node)
                                        val selected = ref == selectedNodeRef
                                        Row(
                                            modifier = Modifier
                                                .fillMaxWidth()
                                                .background(if (selected) MaterialTheme.colorScheme.primary.copy(alpha = 0.1f) else Color.Transparent)
                                                .clickable {
                                                    onSelect(ref)
                                                    onDismiss()
                                                }
                                                .padding(vertical = 10.dp, horizontal = 12.dp),
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Icon(
                                                imageVector = if (selected) Icons.Rounded.RadioButtonChecked else Icons.Rounded.RadioButtonUnchecked,
                                                contentDescription = null,
                                                tint = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                                                modifier = Modifier.size(20.dp)
                                            )
                                            Spacer(modifier = Modifier.width(10.dp))
                                            Column(modifier = Modifier.weight(1f)) {
                                                Text(
                                                    text = node.name,
                                                    style = MaterialTheme.typography.bodyLarge,
                                                    color = MaterialTheme.colorScheme.onSurface
                                                )
                                                Text(
                                                    text = node.group,
                                                    style = MaterialTheme.typography.bodySmall,
                                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                                    maxLines = 1
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                val unknownProfiles = nodesByProfile.keys
                    .filter { it !in knownProfileIds }
                    .sorted()

                unknownProfiles.forEach { profileId ->
                    val itemsForProfile = nodesByProfile[profileId].orEmpty()
                    val isExpanded = expandedProfileId == profileId
                    val enabled = itemsForProfile.isNotEmpty()

                    item(key = "unknown_$profileId") {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(12.dp))
                                .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f))
                                .animateContentSize(animationSpec = tween(durationMillis = 220))
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable(enabled = enabled) {
                                        expandedProfileId = if (isExpanded) null else profileId
                                    }
                                    .padding(vertical = 12.dp, horizontal = 12.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = stringResource(R.string.rulesets_unknown_profile, profileId),
                                        style = MaterialTheme.typography.bodyLarge,
                                        color = if (enabled) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
                                        fontWeight = FontWeight.Medium
                                    )
                                    Text(
                                        text = stringResource(R.string.rulesets_nodes_count, itemsForProfile.size),
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                                Icon(
                                    imageVector = if (isExpanded) Icons.Rounded.ExpandLess else Icons.Rounded.ExpandMore,
                                    contentDescription = null,
                                    tint = if (enabled) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
                                )
                            }

                            AnimatedVisibility(
                                visible = isExpanded,
                                enter = fadeIn(animationSpec = tween(180)),
                                exit = fadeOut(animationSpec = tween(120))
                            ) {
                                LazyColumn(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .heightIn(max = 260.dp)
                                ) {
                                    items(itemsForProfile, key = { it.id }) { node ->
                                        val ref = toNodeRef(node)
                                        val selected = ref == selectedNodeRef
                                        Row(
                                            modifier = Modifier
                                                .fillMaxWidth()
                                                .background(if (selected) MaterialTheme.colorScheme.primary.copy(alpha = 0.1f) else Color.Transparent)
                                                .clickable {
                                                    onSelect(ref)
                                                    onDismiss()
                                                }
                                                .padding(vertical = 10.dp, horizontal = 12.dp),
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Icon(
                                                imageVector = if (selected) Icons.Rounded.RadioButtonChecked else Icons.Rounded.RadioButtonUnchecked,
                                                contentDescription = null,
                                                tint = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                                                modifier = Modifier.size(20.dp)
                                            )
                                            Spacer(modifier = Modifier.width(10.dp))
                                            Column(modifier = Modifier.weight(1f)) {
                                                Text(
                                                    text = node.name,
                                                    style = MaterialTheme.typography.bodyLarge,
                                                    color = MaterialTheme.colorScheme.onSurface
                                                )
                                                Text(
                                                    text = node.group,
                                                    style = MaterialTheme.typography.bodySmall,
                                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                                    maxLines = 1
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            TextButton(
                onClick = onDismiss,
                modifier = Modifier.fillMaxWidth().height(50.dp),
                colors = ButtonDefaults.textButtonColors(contentColor = Neutral500)
            ) {
                Text(stringResource(R.string.common_cancel))
            }
        }
    }
}

@Composable
fun NodeSelectorDialog(
    title: String,
    nodes: List<NodeUi>,
    selectedNodeId: String?,
    testingNodeIds: Set<String> = emptySet(),
    onSelect: (String) -> Unit,
    onDismiss: () -> Unit
) {
    Dialog(onDismissRequest = onDismiss) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .fillMaxHeight(0.75f)
                .background(MaterialTheme.colorScheme.surface, RoundedCornerShape(28.dp))
                .padding(24.dp)
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface
            )

            Spacer(modifier = Modifier.height(16.dp))

            if (nodes.isEmpty()) {
                Box(
                    modifier = Modifier.weight(1f).fillMaxWidth(),
                    contentAlignment = Alignment.Center
                ) {
                    Text(text = stringResource(R.string.dashboard_no_nodes_available))
                }
            } else {
                LazyColumn(
                    modifier = Modifier.weight(1f).fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    items(nodes, key = { it.id }) { node ->
                        val isSelected = node.id == selectedNodeId
                        val isTesting = testingNodeIds.contains(node.id)

                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(
                                    if (isSelected) MaterialTheme.colorScheme.primary.copy(alpha = 0.1f) else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f),
                                    RoundedCornerShape(12.dp)
                                )
                                .border(
                                    width = if (isSelected) 1.5.dp else 0.dp,
                                    color = if (isSelected) MaterialTheme.colorScheme.primary else Color.Transparent,
                                    shape = RoundedCornerShape(12.dp)
                                )
                                .clickable { onSelect(node.id); onDismiss() }
                                .padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                             if (isSelected) {
                                 Icon(Icons.Rounded.Check, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(20.dp))
                             } else {
                                 Spacer(modifier = Modifier.size(20.dp))
                             }
                             Spacer(modifier = Modifier.width(10.dp))
                             Column {
                                 Text(text = node.name, style = MaterialTheme.typography.bodyMedium, fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal)
                                 Text(text = node.protocol, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                             }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            TextButton(
                onClick = onDismiss,
                modifier = Modifier.fillMaxWidth().height(50.dp),
                colors = ButtonDefaults.textButtonColors(contentColor = Neutral500)
            ) {
                Text(stringResource(R.string.common_cancel))
            }
        }
    }
}

@Composable
fun AboutDialog(onDismiss: () -> Unit) {
    val context = LocalContext.current
    val appVersion = "1.0.0" // Hardcoded for now
    val appVersionCode = 1
    val singBoxVersion = "1.9.0-alpha" // Stubbed

    Dialog(onDismissRequest = onDismiss) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(MaterialTheme.colorScheme.surface, RoundedCornerShape(28.dp))
                .padding(24.dp)
        ) {
            Text(
                text = stringResource(R.string.settings_about_kunbox),
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface
            )
            Spacer(modifier = Modifier.height(16.dp))

            Text("KunBox for Android\n\nApp Version: $appVersion ($appVersionCode)\nKernel: $singBoxVersion")

            Spacer(modifier = Modifier.height(24.dp))

            Button(
                onClick = onDismiss,
                modifier = Modifier.fillMaxWidth().height(50.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.primary,
                    contentColor = MaterialTheme.colorScheme.onPrimary
                ),
                shape = RoundedCornerShape(25.dp)
            ) {
                Text(stringResource(R.string.common_ok), fontWeight = FontWeight.Bold)
            }
        }
    }
}
