import { Link } from 'react-router-dom';
import { PageTitle, Section } from '../components/ui';

export default function Settings() {
  return (
    <>
      <PageTitle title="Settings" />
      <div className="max-w-xl space-y-5">
        <Section title="Access">
          <p className="text-[13px] text-muted">This dashboard needs no sign-in or key. Server behaviour (threat-intelligence providers, automated response, thresholds) is configured with environment variables; see the project README.</p>
        </Section>
        <Section title="Chrome extension">
          <p className="text-[13px] text-muted">Download and install it on the <Link to="/setup" className="text-accent hover:underline">Setup</Link> page.</p>
        </Section>
        <Section title="Appearance">
          <p className="text-[13px] text-muted">Switch between light and dark with the button at the top right.</p>
        </Section>
      </div>
    </>
  );
}
