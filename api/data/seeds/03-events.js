const events = [
  {
    event_name: "Chris's Birthday Party",
    event_date: "07/06/2022",
    event_time: "10AM",
    event_location: "Chris's house",
    owner_id: "39c1471d-b4ac-4935-962d-836f01abe3d8",
  },
  {
    event_name: "Dom's Bachelor Party",
    event_date: "10/11/2021",
    event_time: "10PM",
    event_location: "Las Vegas",
    owner_id: "39c1471d-b4ac-4935-962d-836f01abe3d8",
  },
  {
    event_name: "Team 06 Build week Party",
    event_date: "08/27/21",
    event_time: "5PM",
    event_location: "Online",
    owner_id: "39c1471d-b4ac-4935-962d-836f01abe3d8",
  },
  {
    event_name: "Brandon's Boat Party",
    event_date: "09/28/21",
    event_time: "5PM",
    event_location: "Daytona Beach",
    owner_id: "2f6b5812-b10f-485c-ba1b-3d6e76c52f30",
  },
  {
    event_name: "George's Bonfire",
    event_date: "11/28/21",
    event_time: "5PM",
    event_location: "Yosemite",
    owner_id: "fab6a193-3117-444a-9eb1-f8805f0ef1ea",
  },
];

exports.seed = function (knex) {
  return knex("events").insert(events);
};