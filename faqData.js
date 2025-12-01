// faqData.js
module.exports = [
    {
        id: 'accommodation',
        keywords: ['accommodation', 'stay', 'room', 'hostel', 'living'],
        answer: "Accommodation is provided in the college hostels for ₹200/day per person. Separate blocks for boys and girls.",
        action: { text: "Contact Coordinator", link: "/contact" }
    },
    {
        id: 'certificates',
        keywords: ['certificate', 'participation', 'merit'],
        answer: "Certificates will be generated digitally and available on your dashboard 24 hours after the event concludes.",
        action: { text: "My Certificates", link: "/participant/certificates" }
    },
    {
        id: 'refund',
        keywords: ['refund', 'cancel', 'money back'],
        answer: "Registration fees are strictly non-refundable once paid, as per the event policy.",
        action: null // No button needed
    },
    {
        id: 'location',
        keywords: ['location', 'where', 'map', 'venue', 'address'],
        answer: "The fest is held at the Main Campus, Admin Block area. You can find the map in the brochure.",
        action: { text: "View Map", link: "/contact" }
    },
    {
        id: 'food',
        keywords: ['food', 'lunch', 'canteen', 'dinner'],
        answer: "There are food stalls available near the auditorium and the college canteen is open 24/7 during the fest.",
        action: null
    }
];