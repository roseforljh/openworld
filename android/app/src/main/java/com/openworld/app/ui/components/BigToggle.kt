package com.openworld.app.ui.components

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.SizeTransform
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateDp
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.core.updateTransition
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp
import com.openworld.app.R
import kotlinx.coroutines.launch
import kotlin.random.Random

@Composable
fun BigToggle(
    isRunning: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val interactionSource = remember { MutableInteractionSource() }
    val isPressed by interactionSource.collectIsPressedAsState()

    // Scale animation on press
    val scale by animateFloatAsState(
        targetValue = if (isPressed) 0.95f else 1f,
        animationSpec = tween(durationMillis = 150, easing = androidx.compose.animation.core.FastOutSlowInEasing),
        label = "ScaleAnimation"
    )

    // Use updateTransition for coordinated animations
    val transition = updateTransition(targetState = isRunning, label = "BigToggleTransition")

    // Vertical offset animation - 关闭时下�?(使用明确时长�?tween 动画)
    val verticalOffset by transition.animateDp(
        transitionSpec = {
            tween(
                durationMillis = 600,
                easing = androidx.compose.animation.core.FastOutSlowInEasing
            )
        },
        label = "VerticalOffset"
    ) { running ->
        if (running) 0.dp else 20.dp
    }

    // 控制晃动动画�?key，每�?isRunning 变为 true 时重�?    // 使用 mutableStateOf 并显式类型，避免 MutableIntState 委托的兼容性问�?    var shakeKey by remember { androidx.compose.runtime.mutableStateOf(0) }
    LaunchedEffect(isRunning) {
        if (isRunning) {
            shakeKey = shakeKey + 1
        }
    }

    // 晃动动画 - 使用 Animatable 手动控制
    val rotation = remember { Animatable(0f) }

    // 弹跳动画 - 开启时先弹起再落下
    val bounceOffset = remember { Animatable(0f) }

    // 关闭状态时的浮动动�?    val floatOffset = remember { Animatable(0f) }

    // 关闭状态时持续浮动
    LaunchedEffect(isRunning) {
        if (!isRunning) {
            while (true) {
                val targetOffset = Random.nextFloat() * 12f - 6f // -6 �?6 之间随机
                val duration = Random.nextInt(1500, 2500) // 1.5-2.5秒随�?                floatOffset.animateTo(
                    targetValue = targetOffset,
                    animationSpec = tween(duration, easing = androidx.compose.animation.core.FastOutSlowInEasing)
                )
            }
        } else {
            floatOffset.animateTo(0f, animationSpec = tween(300))
        }
    }

    LaunchedEffect(shakeKey) {
        if (isRunning) {
            // 并行执行弹跳和抖动动�?            bounceOffset.snapTo(0f)
            rotation.snapTo(0f)

            // 同时启动弹跳和抖�?            val bounceJob = launch {
                // 慢速弹起到 -100dp (负值表示向�?
                bounceOffset.animateTo(
                    targetValue = -40f,
                    animationSpec = tween(450, easing = androidx.compose.animation.core.FastOutSlowInEasing)
                )
                // 落回�?0dp，使用更慢的弹簧效果
                bounceOffset.animateTo(
                    targetValue = 0f,
                    animationSpec = spring(
                        dampingRatio = Spring.DampingRatioLowBouncy,
                        stiffness = Spring.StiffnessLow
                    )
                )
            }

            val shakeJob = launch {
                // 晃动动画 - 仅在弹起阶段进行 (�?00ms)
                // 快速晃动几�?                if (isRunning) {
                    rotation.animateTo(
                        targetValue = 3f,
                        animationSpec = tween(120, easing = LinearEasing)
                    )
                    rotation.animateTo(
                        targetValue = -3f,
                        animationSpec = tween(240, easing = LinearEasing)
                    )
                    rotation.animateTo(
                        targetValue = 0f,
                        animationSpec = tween(120, easing = LinearEasing)
                    )
                }
                // 确保最后回�?0
                rotation.snapTo(0f)
            }

            // 等待两个动画都完�?            bounceJob.join()
            shakeJob.join()
        } else {
            rotation.snapTo(0f)
            bounceOffset.snapTo(0f)
        }
    }

    // Color animations
    // 移除绿色背景，改为透明或极淡的颜色
    val backgroundColor = Color.Transparent

    // 使用 Box 保持居中，移除硬编码�?padding
    Box(
        contentAlignment = Alignment.Center,
        modifier = modifier
    ) {
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier.offset(y = verticalOffset)
        ) {
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .scale(scale)
                    .offset(y = bounceOffset.value.dp + floatOffset.value.dp)
            ) {
                AnimatedContent(
                    targetState = isRunning,
                    transitionSpec = {
                        fadeIn(animationSpec = tween(400)) togetherWith
                            fadeOut(animationSpec = tween(400)) using
                            SizeTransform(clip = false)
                    },
                    label = "IconCrossfade"
                ) { running ->
                    val res = if (running) R.drawable.gengar_awake else R.drawable.gengar_sleep
                    val imageScale = if (running) 0.75f else 0.75f

                    Image(
                        painter = painterResource(id = res),
                        contentDescription = if (running) "Running" else "Idle",
                        modifier = Modifier
                            .scale(imageScale)
                            .offset(x = 0.dp, y = 32.dp)
                            .graphicsLayer {
                                rotationZ = rotation.value
                            }
                    )
                }

                Box(
                    modifier = Modifier
                        .size(200.dp)
                        .clip(CircleShape)
                        .background(backgroundColor)
                        .clickable(
                            interactionSource = interactionSource,
                            indication = null,
                            onClick = onClick
                        )
                )
            }
        }
    }
}







