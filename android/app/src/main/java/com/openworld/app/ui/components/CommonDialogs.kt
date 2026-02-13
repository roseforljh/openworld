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
