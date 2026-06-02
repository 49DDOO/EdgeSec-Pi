import { redirect } from "next/navigation";

export default function LegacyDetectionSettingsPage() {
  redirect("/settings/sources/wazuh/detections");
}
