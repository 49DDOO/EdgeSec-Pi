"use client";

import { useCallback, useEffect, useState } from "react";
import type { InvestigationEvidence, InvestigationMessage } from "@/lib/types";

const STORAGE_KEY = "edgesec.investigation.sessions.v1";

export interface InvestigationSession {
  messages: InvestigationMessage[];
  evidence: InvestigationEvidence[];
  updatedAt: string;
}

type InvestigationSessions = Record<string, InvestigationSession>;

const emptySession = (): InvestigationSession => ({
  messages: [],
  evidence: [],
  updatedAt: "",
});

const readSessions = (): InvestigationSessions => {
  if (typeof window === "undefined") return {};
  try {
    const raw = window.sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
};

export function useInvestigationSessions() {
  const [sessions, setSessions] = useState<InvestigationSessions>(() => readSessions());

  useEffect(() => {
    if (typeof window === "undefined") return;
    window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(sessions));
  }, [sessions]);

  const getSession = useCallback(
    (key: string | null | undefined) => {
      if (!key) return emptySession();
      return sessions[key] || emptySession();
    },
    [sessions]
  );

  const saveSession = useCallback(
    (key: string, values: Pick<InvestigationSession, "messages" | "evidence">) => {
      setSessions((current) => ({
        ...current,
        [key]: {
          messages: values.messages,
          evidence: values.evidence,
          updatedAt: new Date().toISOString(),
        },
      }));
    },
    []
  );

  const clearSession = useCallback((key: string) => {
    setSessions((current) => {
      const next = { ...current };
      delete next[key];
      return next;
    });
  }, []);

  return { getSession, saveSession, clearSession };
}
