mmio_regs = {
    0x2000: "PMR_SYS_CTRL1",
    0x2001: "PMR_SYS_CTRL2",
    0x2002: "PMR_SYS_CTRL3",

    0x2008: "PMR_SEC_CTRL",
    0x2009: "PMR_SEC_CNT_LO",
    0x200A: "PMR_SEC_CNT_MID",
    0x200B: "PMR_SEC_CNT_HI",

    0x2010: "PMR_SYS_BATT",

    0x2018: "PMR_TMR1_SCALE",
    0x2019: "PMR_TMR1_ENA_OS",
    0x2019: "PMR_TMR1_OSC",
    0x201A: "PMR_TMR2_SCALE",
    0x201B: "PMR_TMR2_OSC",
    0x201C: "PMR_TMR3_SCALE",
    0x201D: "PMR_TMR3_OSC",

    0x2020: "PMR_IRQ_PRI1",
    0x2021: "PMR_IRQ_PRI2",
    0x2022: "PMR_IRQ_PRI3",
    0x2023: "PMR_IRQ_ENA1",
    0x2024: "PMR_IRQ_ENA2",
    0x2025: "PMR_IRQ_ENA3",
    0x2026: "PMR_IRQ_ENA4",
    0x2027: "PMR_IRQ_ACT1",
    0x2028: "PMR_IRQ_ACT2",
    0x2029: "PMR_IRQ_ACT3",
    0x202A: "PMR_IRQ_ACT4",

    0x2030: "PMR_TMR1_CTRL_L",
    0x2031: "PMR_TMR1_CTRL_H",
    0x2032: "PMR_TMR1_PRE_L",
    0x2033: "PMR_TMR1_PRE_H",
    0x2034: "PMR_TMR1_PVT_L",
    0x2035: "PMR_TMR1_PVT_H",
    0x2036: "PMR_TMR1_CNT_L",
    0x2037: "PMR_TMR1_CNT_H",

    0x2038: "PMR_TMR2_CTRL_L",
    0x2039: "PMR_TMR2_CTRL_H",
    0x203A: "PMR_TMR2_PRE_L",
    0x203B: "PMR_TMR2_PRE_H",
    0x203C: "PMR_TMR2_PVT_L",
    0x203D: "PMR_TMR2_PVT_H",
    0x203E: "PMR_TMR2_CNT_L",
    0x203F: "PMR_TMR2_CNT_H",

    0x2040: "PMR_TMR256_CTRL",
    0x2041: "PMR_TMR256_CNT",

    0x2044: "PMR_REG_44",
    0x2045: "PMR_REG_45",
    0x2046: "PMR_REG_46",
    0x2047: "PMR_REG_47",

    0x2048: "PMR_TMR3_CTRL_L",
    0x2049: "PMR_TMR3_CTRL_H",
    0x204A: "PMR_TMR3_PRE_L",
    0x204B: "PMR_TMR3_PRE_H",
    0x204C: "PMR_TMR3_PVT_L",
    0x204D: "PMR_TMR3_PVT_H",
    0x204E: "PMR_TMR3_CNT_L",
    0x204F: "PMR_TMR3_CNT_H",

    0x2050: "PMR_REG_50",
    0x2051: "PMR_REG_51",
    0x2052: "PMR_KEY_PAD",
    0x2053: "PMR_REG_53",
    0x2054: "PMR_REG_54",
    0x2055: "PMR_REG_55",

    0x2060: "PMR_IO_DIR",
    0x2061: "PMR_IO_DATA",
    0x2062: "PMR_REG_62",

    0x2070: "PMR_AUD_CTRL",
    0x2071: "PMR_AUD_VOL",

    0x2080: "PMR_PRC_MODE",
    0x2081: "PMR_PRC_RATE",
    0x2082: "PMR_PRC_MAP_LO",
    0x2083: "PMR_PRC_MAP_MID",
    0x2084: "PMR_PRC_MAP_HI",
    0x2085: "PMR_PRC_SCROLL_",
    0x2086: "PMR_PRC_SCROLL_",
    0x2087: "PMR_PRC_SPR_LO",
    0x2088: "PMR_PRC_SPR_MID",
    0x2089: "PMR_PRC_SPR_HI",
    0x208A: "PMR_PRC_CNT",

    0x20FE: "PMR_LCD_CTRL",
    0x20FF: "PMR_LCD_DATA",

}

default_symbols = {
    0x002102: "reset_vector",
    0x002108: "prc_frame_copy_irq",
    0x00210E: "prc_render_irq",
    0x002114: "timer_2h_underflow_irq",
    0x00211A: "timer_2l_underflow_irq",
    0x002120: "timer_1h_underflow_irq",
    0x002126: "timer_1l_underflow_irq",
    0x00212C: "timer_3h_underflow_irq",
    0x002132: "timer_3_cmp_irq",
    0x002138: "timer_32hz_irq",
    0x00213E: "timer_8hz_irq",
    0x002144: "timer_2hz_irq",
    0x00214A: "timer_1hz_irq",
    0x002150: "ir_rx_irq",
    0x002156: "shake_irq",
    0x00215C: "key_power_irq",
    0x002162: "key_right_irq",
    0x002168: "key_left_irq",
    0x00216E: "key_down_irq",
    0x002174: "key_up_irq",
    0x00217A: "key_c_irq",
    0x002180: "key_b_irq",
    0x002186: "key_a_irq",
    0x00218C: "unknown_irq0",
    0x002192: "unknown_irq1",
    0x002198: "unknown_irq2",
    0x00219E: "cartridge_irq",
}