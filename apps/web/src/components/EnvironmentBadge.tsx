/**
 * Which deployment you are looking at.
 *
 * The console gave no indication at all. A sandbox deployment and a live one presented
 * identical screens, which in a product whose entire purpose is moving money invites two
 * expensive mistakes in opposite directions: rehearsing against real funds, or releasing a
 * real payroll into a sandbox and believing it went out.
 *
 * `movesRealMoney` is the honest test, and it is deliberately stricter than the deployment
 * name: a production deployment still pointed at the Daraja sandbox pays nobody, and saying
 * "Production" there would be a lie the operator acts on.
 */

import type { SessionResponse } from '../lib/api.js';

type Deployment = SessionResponse['deployment'];

export function EnvironmentBadge({ deployment }: { deployment: Deployment }) {
  if (deployment.movesRealMoney) {
    return (
      <span className="env-badge" data-env="live" title="Payments released here move real money">
        <span className="env-dot" aria-hidden="true" />
        Live
      </span>
    );
  }

  // Everything that is not fully live says so in the same breath as why, since "Staging"
  // alone does not tell an operator whether a release would reach anybody.
  const label =
    deployment.environment === 'production' ? 'Production · sandbox rail' : 'Test environment';

  return (
    <span
      className="env-badge"
      data-env="test"
      title={`ENVIRONMENT=${deployment.environment}, Daraja=${deployment.darajaEnvironment}. No payment released here reaches a real recipient.`}
    >
      <span className="env-dot" aria-hidden="true" />
      {label}
    </span>
  );
}
