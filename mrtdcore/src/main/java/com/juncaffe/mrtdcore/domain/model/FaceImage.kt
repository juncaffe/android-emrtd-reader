/*
 * Copyright 2026 JunCaffe
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.juncaffe.mrtdcore.domain.model

import com.juncaffe.mrtdcore.security.SecureByteArray
import com.juncaffe.mrtdcore.security.Wipeable

/** DG2 얼굴 이미지 인코딩 포맷 (ISO/IEC 19794-5). */
enum class ImageFormat { JPEG, JPEG2000 }

/**
 * DG2 에서 추출한 얼굴 이미지. 디코딩(Bitmap 변환)은 Android 의존이므로 상위(:ePassport) 책임이다.
 * 이미지 바이트는 민감 PII 이므로 [SecureByteArray] 로 보관하고 [wipe] 로 0화한다.
 *
 * @property format JPEG 또는 JPEG2000 @property imageData 원시 이미지 바이트
 * @property width 픽셀 너비 @property height 픽셀 높이
 */
class FaceImage(
    val format: ImageFormat,
    val imageData: SecureByteArray,
    val width: Int,
    val height: Int,
) : Wipeable {
    override fun wipe() = imageData.wipe()
}
