"use client";

import * as React from "react";

type Theme = "light" | "dark" | "system";
type ResolvedTheme = "light" | "dark";

interface ThemeProviderProps {
  children: React.ReactNode;
  defaultTheme?: Theme;
  attribute?: "class";
  enableSystem?: boolean;
  disableTransitionOnChange?: boolean;
}

interface ThemeContextValue {
  theme: Theme;
  resolvedTheme: ResolvedTheme;
  setTheme: (theme: Theme) => void;
}

const STORAGE_KEY = "edgesec-theme";
const ThemeContext = React.createContext<ThemeContextValue | null>(null);

function systemTheme(): ResolvedTheme {
  if (typeof window === "undefined") return "light";
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function storedTheme(defaultTheme: Theme): Theme {
  if (typeof window === "undefined") return defaultTheme;
  const value = window.localStorage.getItem(STORAGE_KEY);
  return value === "light" || value === "dark" || value === "system" ? value : defaultTheme;
}

function applyTheme(theme: Theme, disableTransition: boolean) {
  const resolved = theme === "system" ? systemTheme() : theme;
  const root = document.documentElement;
  const previousTransition = root.style.transition;

  if (disableTransition) {
    root.style.transition = "none";
  }

  root.classList.toggle("dark", resolved === "dark");
  root.style.colorScheme = resolved;

  if (disableTransition) {
    window.requestAnimationFrame(() => {
      root.style.transition = previousTransition;
    });
  }
}

export function ThemeProvider({
  children,
  defaultTheme = "system",
  disableTransitionOnChange = false,
}: ThemeProviderProps) {
  const [theme, setThemeState] = React.useState<Theme>(() => storedTheme(defaultTheme));
  const [systemIsDark, setSystemIsDark] = React.useState(() =>
    typeof window === "undefined" ? false : systemTheme() === "dark"
  );
  const resolvedTheme: ResolvedTheme = theme === "system" ? (systemIsDark ? "dark" : "light") : theme;

  React.useEffect(() => {
    applyTheme(theme, disableTransitionOnChange);
  }, [disableTransitionOnChange, theme]);

  React.useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => {
      setSystemIsDark(media.matches);
      if (theme === "system") {
        applyTheme("system", disableTransitionOnChange);
      }
    };

    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, [disableTransitionOnChange, theme]);

  const setTheme = React.useCallback((nextTheme: Theme) => {
    window.localStorage.setItem(STORAGE_KEY, nextTheme);
    setThemeState(nextTheme);
  }, []);

  const value = React.useMemo(
    () => ({ theme, resolvedTheme, setTheme }),
    [resolvedTheme, setTheme, theme]
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme() {
  const context = React.useContext(ThemeContext);
  if (!context) {
    throw new Error("useTheme must be used within ThemeProvider");
  }
  return context;
}
