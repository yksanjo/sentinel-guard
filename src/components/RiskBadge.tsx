import React from 'react';
import { Box, Text } from 'ink';
import { RiskCategory } from '../utils/risk-calculator.js';

interface RiskBadgeProps {
  score: number;
  size?: 'small' | 'medium' | 'large';
  showLabel?: boolean;
}

const getRiskCategory = (score: number): RiskCategory => {
  if (score >= 80) {
    return { level: 'critical', score, color: '#FF4444', emoji: '🔴' };
  }
  if (score >= 60) {
    return { level: 'high', score, color: '#FF8800', emoji: '🟠' };
  }
  if (score >= 40) {
    return { level: 'medium', score, color: '#FFCC00', emoji: '🟡' };
  }
  if (score >= 20) {
    return { level: 'low', score, color: '#88CC00', emoji: '🟢' };
  }
  return { level: 'safe', score, color: '#00AA00', emoji: '✅' };
};

const getColor = (level: string): string => {
  switch (level) {
    case 'critical':
      return 'red';
    case 'high':
      return 'redBright';
    case 'medium':
      return 'yellow';
    case 'low':
      return 'green';
    case 'safe':
      return 'greenBright';
    default:
      return 'gray';
  }
};

export const RiskBadge: React.FC<RiskBadgeProps> = ({ 
  score, 
  size = 'medium',
  showLabel = true 
}) => {
  const category = getRiskCategory(score);
  const color = getColor(category.level);

  const renderSmall = () => (
    <Text color={color} bold>
      {category.emoji} {score}
    </Text>
  );

  const renderMedium = () => (
    <Box>
      <Text color={color} bold>
        {category.emoji} {score}/100
      </Text>
      {showLabel && (
        <Text color={color}> ({category.level.toUpperCase()})</Text>
      )}
    </Box>
  );

  const renderLarge = () => (
    <Box flexDirection="column">
      <Box>
        <Text color={color} bold>
          {category.emoji} RISK SCORE: {score}/100
        </Text>
      </Box>
      {showLabel && (
        <Box marginTop={1}>
          <Text backgroundColor={color} color="white" bold>
            {' '} {category.level.toUpperCase()} {' '}
          </Text>
        </Box>
      )}
    </Box>
  );

  switch (size) {
    case 'small':
      return renderSmall();
    case 'large':
      return renderLarge();
    default:
      return renderMedium();
  }
};

export default RiskBadge;
