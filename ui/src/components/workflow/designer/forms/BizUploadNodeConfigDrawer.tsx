import { useTranslation } from "react-i18next";
import { type FlowNodeEntity } from "@flowgram.ai/fixed-layout-editor";
import { App, Form } from "antd";

import { useCertificateCompatibilityPreview } from "@/hooks/useCertificateCompatibility";
import { compatibilityStateText, initialPreviewState, previewIdentity } from "@/utils/certificateCompatibility";

import { NodeConfigDrawer } from "./_shared";
import BizUploadNodeConfigForm from "./BizUploadNodeConfigForm";
import { NodeType } from "../nodes/typings";

export interface BizUploadNodeConfigDrawerProps {
  afterClose?: () => void;
  loading?: boolean;
  node: FlowNodeEntity;
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
}

const BizUploadNodeConfigDrawer = ({ node, ...props }: BizUploadNodeConfigDrawerProps) => {
  if (node.flowNodeType !== NodeType.BizUpload) {
    console.warn(`[certimate] current workflow node type is not: ${NodeType.BizUpload}`);
  }

  const { i18n, t } = useTranslation();

  const [formInst] = Form.useForm();
  const { message } = App.useApp();
  const source = Form.useWatch("source", { form: formInst, preserve: true });
  const certificate = Form.useWatch("certificate", { form: formInst, preserve: true });
  const preview = useCertificateCompatibilityPreview(source, certificate, !!props.open);

  const handleSaved = (values: Record<string, unknown>) => {
    const savedSource = values.source as string | undefined;
    const savedCertificate = values.certificate as string | undefined;
    const state = preview.key === previewIdentity(savedSource, savedCertificate) ? preview.state : initialPreviewState(savedSource, savedCertificate);
    const bounds =
      state.phase === "ready" && state.result.oldestVersion && state.result.newestVersion
        ? t("certificate.compatibility.bounds", { oldest: state.result.oldestVersion, newest: state.result.newestVersion })
        : "";
    message.info(
      [`${t("certificate.compatibility.title")}: ${compatibilityStateText(state, t)}`, t("certificate.compatibility.basis"), bounds].filter(Boolean).join(" · ")
    );
  };

  return (
    <NodeConfigDrawer
      anchor={{
        items: BizUploadNodeConfigForm.getAnchorItems({ i18n }),
      }}
      form={formInst}
      node={node}
      onSaved={handleSaved}
      {...props}
    >
      <BizUploadNodeConfigForm form={formInst} node={node} compatibility={preview.state} />
    </NodeConfigDrawer>
  );
};

export default BizUploadNodeConfigDrawer;
