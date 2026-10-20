import { useTranslation } from "react-i18next";
import { Collapse, Space, Table, Tag, Tooltip, Typography } from "antd";
import dayjs from "dayjs";

import { type CertificateCompatibilityState } from "@/domain/certificateCompatibility";
import { compatibilityReason, compatibilityStateText } from "@/utils/certificateCompatibility";

export interface CertificateCompatibilityProps {
  state?: CertificateCompatibilityState;
  detailed?: boolean;
}

const CertificateCompatibility = ({ state = { phase: "loading" }, detailed = false }: CertificateCompatibilityProps) => {
  const { t } = useTranslation();
  const result = state.phase === "ready" ? state.result : undefined;
  const color = result?.status === "compatible" ? "success" : result?.status === "invalid" || result?.status === "not_trusted" ? "warning" : "default";
  const summary = compatibilityStateText(state, t);
  const bounds =
    result?.oldestVersion && result?.newestVersion ? t("certificate.compatibility.bounds", { oldest: result.oldestVersion, newest: result.newestVersion }) : "";
  const reason = result ? compatibilityReason(result.reason, t) : "";
  const hint = [summary, bounds, reason, t("certificate.compatibility.scope")].filter(Boolean).join(" · ");

  return (
    <Space orientation="vertical" size="small" className="max-w-full" style={{ width: detailed ? "100%" : undefined }}>
      <Tooltip title={hint}>
        <Tag color={color} style={{ maxWidth: "100%", whiteSpace: "normal", marginInlineEnd: 0 }}>
          {summary}
        </Tag>
      </Tooltip>
      {result && (
        <Typography.Text type="secondary" className="text-xs">
          {bounds}
        </Typography.Text>
      )}
      {detailed && (
        <>
          <Typography.Text type="secondary" className="text-xs">
            {t("certificate.compatibility.scope")}
          </Typography.Text>
          {result && (
            <>
              <Typography.Text>{reason}</Typography.Text>
              <Typography.Text type="secondary" className="text-xs">
                {t("certificate.compatibility.metadata", { version: result.dataVersion, time: dayjs(result.evaluatedAt).format("YYYY-MM-DD HH:mm:ss") })}
              </Typography.Text>
              <Collapse
                size="small"
                items={[
                  {
                    key: "profiles",
                    label: t("certificate.compatibility.details"),
                    children: (
                      <Table
                        size="small"
                        pagination={false}
                        rowKey="version"
                        dataSource={result.profiles}
                        scroll={{ x: 540 }}
                        columns={[
                          { title: "Android", dataIndex: "version", width: 80 },
                          {
                            title: t("certificate.compatibility.profile_status"),
                            dataIndex: "status",
                            width: 120,
                            render: (status: string) =>
                              t(`certificate.compatibility.profile.${status}`, { defaultValue: t("certificate.compatibility.profile.unknown") }),
                          },
                          {
                            title: t("certificate.compatibility.profile_reason"),
                            dataIndex: "reason",
                            render: (value: string) => compatibilityReason(value, t),
                          },
                          {
                            title: t("certificate.compatibility.roots"),
                            key: "roots",
                            render: (_, profile) =>
                              profile.roots.length ? (
                                <Space orientation="vertical" size={0}>
                                  {[...new Map(profile.roots.map((root) => [root.name, root])).values()].map((root) => (
                                    <Tooltip
                                      key={root.name}
                                      title={profile.roots
                                        .filter((item) => item.name === root.name)
                                        .map((item) => item.fingerprint)
                                        .join(" / ")}
                                    >
                                      <span>{root.name}</span>
                                    </Tooltip>
                                  ))}
                                </Space>
                              ) : (
                                "—"
                              ),
                          },
                        ]}
                      />
                    ),
                  },
                ]}
              />
            </>
          )}
        </>
      )}
    </Space>
  );
};

export default CertificateCompatibility;
