import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

class SezamColors {
  static const bg = Color(0xFF0D1117);
  static const bgCard = Color(0xFF161B22);
  static const bgElevated = Color(0xFF1C2333);
  static const bgInput = Color(0xFF21262D);
  static const accent = Color(0xFF00BCD4);
  static const accentLight = Color(0xFF26C6DA);
  static const accentDim = Color(0xFF00838F);
  static const accentGlow = Color(0x3300BCD4);
  static const text = Color(0xFFE6EDF3);
  static const textSecondary = Color(0xFF8B949E);
  static const textMuted = Color(0xFF484F58);
  static const border = Color(0xFF30363D);
  static const borderAccent = Color(0xFF1A6B75);
  static const success = Color(0xFF3FB950);
  static const error = Color(0xFFF85149);
  static const warning = Color(0xFFD29922);
  static const sensitive = Color(0xFFF78166);
  static const folder = Color(0xFF26C6DA);
  static const entry = Color(0xFF8B949E);
}

class SezamTheme {
  static ThemeData get dark {
    return ThemeData(
      useMaterial3: true,
      brightness: Brightness.dark,
      scaffoldBackgroundColor: SezamColors.bg,
      colorScheme: const ColorScheme.dark(
        primary: SezamColors.accent,
        secondary: SezamColors.accentLight,
        surface: SezamColors.bgCard,
        error: SezamColors.error,
        onPrimary: Colors.white,
        onSurface: SezamColors.text,
        outline: SezamColors.border,
      ),
      appBarTheme: const AppBarTheme(
        backgroundColor: SezamColors.bg,
        foregroundColor: SezamColors.text,
        elevation: 0,
        centerTitle: false,
        systemOverlayStyle: SystemUiOverlayStyle(
          statusBarColor: Colors.transparent,
          statusBarIconBrightness: Brightness.light,
          systemNavigationBarColor: SezamColors.bg,
        ),
      ),
      cardTheme: CardThemeData(
        color: SezamColors.bgCard,
        elevation: 0,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
          side: const BorderSide(color: SezamColors.border, width: 1),
        ),
        margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: SezamColors.bgInput,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: const BorderSide(color: SezamColors.border),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: const BorderSide(color: SezamColors.border),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: const BorderSide(color: SezamColors.accent, width: 2),
        ),
        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
        hintStyle: const TextStyle(color: SezamColors.textMuted),
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: SezamColors.accent,
          foregroundColor: Colors.white,
          elevation: 0,
          padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 16),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
          textStyle: const TextStyle(
            fontSize: 16,
            fontWeight: FontWeight.w600,
            letterSpacing: 0.5,
          ),
        ),
      ),
      textButtonTheme: TextButtonThemeData(
        style: TextButton.styleFrom(
          foregroundColor: SezamColors.accent,
        ),
      ),
      bottomNavigationBarTheme: const BottomNavigationBarThemeData(
        backgroundColor: SezamColors.bgCard,
        selectedItemColor: SezamColors.accent,
        unselectedItemColor: SezamColors.textMuted,
        type: BottomNavigationBarType.fixed,
        elevation: 0,
      ),
      floatingActionButtonTheme: const FloatingActionButtonThemeData(
        backgroundColor: SezamColors.accent,
        foregroundColor: Colors.white,
        elevation: 4,
      ),
      dialogTheme: DialogThemeData(
        backgroundColor: SezamColors.bgElevated,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(20),
        ),
      ),
      snackBarTheme: SnackBarThemeData(
        backgroundColor: SezamColors.bgElevated,
        contentTextStyle: const TextStyle(color: SezamColors.text),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
        ),
        behavior: SnackBarBehavior.floating,
      ),
      dividerTheme: const DividerThemeData(
        color: SezamColors.border,
        thickness: 1,
      ),
      textTheme: const TextTheme(
        headlineLarge: TextStyle(
          color: SezamColors.text,
          fontSize: 28,
          fontWeight: FontWeight.bold,
          letterSpacing: -0.5,
        ),
        headlineMedium: TextStyle(
          color: SezamColors.text,
          fontSize: 22,
          fontWeight: FontWeight.bold,
        ),
        titleLarge: TextStyle(
          color: SezamColors.text,
          fontSize: 18,
          fontWeight: FontWeight.w600,
        ),
        titleMedium: TextStyle(
          color: SezamColors.text,
          fontSize: 16,
          fontWeight: FontWeight.w500,
        ),
        bodyLarge: TextStyle(
          color: SezamColors.text,
          fontSize: 15,
        ),
        bodyMedium: TextStyle(
          color: SezamColors.textSecondary,
          fontSize: 14,
        ),
        labelLarge: TextStyle(
          color: SezamColors.textSecondary,
          fontSize: 12,
          fontWeight: FontWeight.w600,
          letterSpacing: 1.2,
        ),
      ),
    );
  }
}
