/**
 * Example usage in a Web Extension (e.g., Chrome Extension)
 *
 * This can be used in a background script or a popup.
 */

// Import the client (assuming you use a bundler like Webpack or Vite)
// import { EmailScannerClient } from './client';

async function handleNewEmail(emailSender, emailBody) {
  const client = new EmailScannerClient('http://localhost:8000', 'YOUR_API_KEY');

  try {
    console.log('Scanning email...');
    const result = await client.scanEmail({
      email_address: emailSender,
      email_text: emailBody
    });

    console.log('Scan Results:', result);

    // Example: How to use the results in your UI
    displayResults(result);

  } catch (error) {
    console.error('Failed to scan email:', error);
  }
}

function displayResults(result) {
  // 1. Show the overall score and color based on risk level
  const riskColors = {
    'LOW': '#4CAF50',      // Green
    'MEDIUM': '#FFC107',   // Yellow
    'HIGH': '#FF9800',     // Orange
    'CRITICAL': '#F44336'  // Red
  };

  const mainColor = riskColors[result.risk_level];
  console.log(`Risk Level: %c${result.risk_level}`, `color: ${mainColor}; font-weight: bold`);
  console.log(`Scam Score: ${result.scam_score}/100`);

  // 2. Display labels as badges
  if (result.labels.length > 0) {
    console.log('Alerts:', result.labels.join(' | '));
  }

  // 3. Show recommendations
  console.log('Recommendations:');
  result.recommendations.forEach(rec => console.log(`- ${rec}`));
}

// In a real extension, you might listen to events from Gmail or Outlook
// chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
//   if (request.type === 'SCAN_EMAIL') {
//     handleNewEmail(request.emailAddress, request.emailText);
//   }
// });
