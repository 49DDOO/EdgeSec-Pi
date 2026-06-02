import type { Alert } from "@/lib/types";

export interface ActionableAlertGroup {
  key: string;
  primary: Alert;
  alerts: Alert[];
}
