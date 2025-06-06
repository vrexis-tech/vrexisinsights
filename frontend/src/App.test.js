import { render, screen } from '@testing-library/react';
import App from './App';

test('renders Vrexis Insights heading', () => {
  render(<App />);
  expect(screen.getByText(/Vrexis Insights/i)).toBeInTheDocument();
});
